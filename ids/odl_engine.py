"""XAI-IDS on OpenDaylight (RESTCONF) instead of Ryu.

Why this exists: the same detection-and-response pipeline, driven by a different
controller. It shows that the CGRE is controller-agnostic — the ML, SHAP and gating
layers do not change, only the southbound plumbing does (RESTCONF polling and
`sal-flow` RPCs instead of Ryu's OpenFlow event loop).

Two consequences of ODL's design that shape this file:

1. **ODL's L2Switch is port-based only.** Its flows match `in-port`, never `ipv4-source`,
   so they cannot produce the per-source features the detector needs. We therefore
   install our own L3 forwarding rules (src, dst, proto, service port) and read *those*
   counters. L2Switch still handles the table-miss and ARP.
2. **RESTCONF polling is heavier than an in-process event loop.** Every round is two
   HTTP requests per switch (one RPC-free GET returns all flows for a node, so one per
   switch), which we measure and report rather than hide.

    python3 -m ids.odl_engine --odl http://172.20.0.1:8182 --mode detect --duration 600

Endpoints mirror the Ryu app (`/xai/rounds`, `/xai/decisions`, `/xai/mitigations`,
`/xai/status`, `DELETE /xai/mitigations/<ip>`), so the dashboard can point at either
controller by changing one URL.
"""
import argparse
import csv
import json
import os
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ids import config as C
from ids.features import FeatureExtractor, FlowRecord
from ids.odl import ODL, ODLError
from ids.policy import ALERT, BLOCK, NONE, RATE_LIMIT, ResponseEngine

SECURITY_TABLE, FORWARD_TABLE = 0, 0   # ODL's L2Switch also lives in table 0
FORWARD_PRIORITY = 10
MITIGATION_PRIORITY = 1000
SERVICE_PRIORITY = 50        # our L3 rules, above L2Switch's port rules (priority 2)

# Static path map derived from topology/topo.py. Mininet numbers ports in the order
# interfaces are created, and the inter-switch links are built *before* the host links:
#   s1: eth1 -> s2, eth2 -> s3
#   s2: eth1 -> s1, eth2..eth5 -> h1..h4
#   s3: eth1 -> s1, eth2..eth5 -> h5..h8
# (confirmed against `ovs-ofctl show` and ODL's node-connector inventory). Keeping this
# explicit is honest: ODL L2Switch has no IP routing, so the operator declares the paths.
HOST_SWITCH = {
    "10.0.0.1": "openflow:2", "10.0.0.2": "openflow:2",
    "10.0.0.3": "openflow:2", "10.0.0.4": "openflow:2",
    "10.0.0.5": "openflow:3", "10.0.0.6": "openflow:3",
    "10.0.0.7": "openflow:3", "10.0.0.8": "openflow:3",
}
HOST_PORT = {"10.0.0.1": 2, "10.0.0.2": 3, "10.0.0.3": 4, "10.0.0.4": 5,
             "10.0.0.5": 2, "10.0.0.6": 3, "10.0.0.7": 4, "10.0.0.8": 5}
UPLINK = {"openflow:2": 1, "openflow:3": 1}          # edge -> core port
CORE_DOWNLINK = {"openflow:2": 1, "openflow:3": 2}   # core -> edge port


def egress_port(switch, dst):
    """Port a packet to `dst` must leave `switch` through, or None if it cannot reach it."""
    dst_sw = HOST_SWITCH.get(dst)
    if dst_sw is None:
        return None
    if switch == dst_sw:
        return HOST_PORT[dst]
    if switch == "openflow:1":
        return CORE_DOWNLINK[dst_sw]
    return UPLINK[switch]        # edge -> core


def _match_fields(match):
    """Flatten an ODL JSON match into the tuple features.py understands."""
    src = match.get("ipv4-source")
    dst = match.get("ipv4-destination")
    if not src or not dst:
        return None
    proto = (match.get("ip-match") or {}).get("ip-protocol")
    sport = dport = None
    for key, tport, uport in (("tcp-match", "tcp-source-port", "tcp-destination-port"),
                              ("udp-match", "udp-source-port", "udp-destination-port")):
        l4 = match.get(key)
        if l4:
            sport = l4.get(tport)
            dport = l4.get(uport)
    return (src.split("/")[0], dst.split("/")[0], proto, sport, dport)


class ODLIdsEngine:
    """Polls ODL, runs the detector/CGRE, and installs mitigation through RESTCONF."""

    def __init__(self, odl_url="http://127.0.0.1:8182", user="admin", password="admin",
                 mode="detect", interval=None):
        self.odl = ODL(odl_url, user, password)
        self.mode = mode
        self.interval = interval or C.POLL_INTERVAL
        self.extractor = FeatureExtractor(self.interval)
        self.engine = ResponseEngine()
        self.detector = self.explainer = None
        if mode != "collect":
            from ids.detector import Detector
            from ids.explainer import Explainer
            self.detector = Detector()
            self.explainer = Explainer(self.detector)

        self.nodes = []
        self.src_port = {}            # (node, src ip) -> ingress port of that source
        self.installed = set()        # forwarding rules we added
        self.decisions = deque(maxlen=600)
        self.rounds = deque(maxlen=450)
        self.mitigations = {}         # src ip -> {"action", "expires"}
        self.poll_ms = deque(maxlen=60)
        self._baseline_rounds = 1   # first round only seeds counter deltas
        self.feature_file = None
        self.lock = threading.Lock()

    # ------------------------------------------------------------------ setup
    def refresh_nodes(self):
        self.nodes = self.odl.nodes()
        return self.nodes

    def ensure_forwarding(self, node, src, dst, proto=None, out_port=None):
        """Install one L3 forwarding rule (source -> destination) if not already present.

        The egress port comes from the static path map above; ODL's L2Switch cannot
        resolve it because it has no IP routing."""
        key = (node, src, dst, proto)
        if key in self.installed:
            return False
        out_port = out_port or egress_port(node, dst)
        if out_port is None:
            return False
        match = ODL.build_match(ipv4_src=src, ipv4_dst=dst, proto=proto)
        self.odl.add_flow(node, match, out_port=out_port, priority=SERVICE_PRIORITY,
                          name=f"xai-fwd-{src}-{dst}-{proto}")
        self.installed.add(key)
        return True

    def provision(self, protos=(1, 6, 17)):
        """Install the full mesh of per-(source, destination, protocol) rules on every
        switch, so counters exist for every host pair from the first packet.

        This is the closest ODL equivalent of the Ryu app's reactive L3/L4 forwarding.
        It is coarser than Ryu: without Packet-In visibility we cannot learn flow keys
        on demand, so the mesh is declared up front."""
        ips = sorted(HOST_SWITCH)
        self.installed.clear()   # a re-provision replaces the map; rules on the switch persist
        for node in self.nodes:
            for src in ips:
                for dst in ips:
                    if src == dst:
                        continue
                    for proto in protos:
                        try:
                            self.ensure_forwarding(node, src, dst, proto)
                        except ODLError as e:
                            print(f"[odl] rule {src}->{dst}/{proto} on {node} failed: {e}")
        print(f"[odl] provisioned {len(self.installed)} forwarding rules "
              f"across {len(self.nodes)} switches")
        return len(self.installed)

    # ------------------------------------------------------------------ one polling round
    def poll_once(self):
        """Read per-flow counters from every switch, build features, detect, respond.

        A source's traffic crosses every switch on the path, so the same packet is counted
        on 2-3 switches. The Ryu app resolves this by keeping the switch that saw the most
        packets (the ingress edge). Here the ingress switch is known statically: a source
        lives on exactly one edge switch (HOST_SWITCH), so we filter to that switch and
        never double count.

        Returns the per-host snapshot for the round (same shape as the Ryu app)."""
        t0 = time.perf_counter()
        records = []
        for node in self.nodes or self.refresh_nodes():
            dpid = int(node.split(":")[1])
            for f in self.odl.flow_stats(node, table=FORWARD_TABLE):
                if f["priority"] != SERVICE_PRIORITY:
                    continue
                fields = _match_fields(f["match"])
                if fields is None:
                    continue
                src, dst, proto, sport, dport = fields
                if HOST_SWITCH.get(src) != node:      # only the source's ingress switch
                    continue
                if f["packets"] == 0:                 # a declared rule that never matched is
                    continue                          # not an active flow (Ryu only sees live
                                                      # entries); counting it would inflate
                                                      # n_flows and n_dst_ips
                # ODL reports a flow's `duration` from when it was entered into the
                # datastore, and a re-installed rule carries its original age. Statically
                # provisioned rules therefore age with the mesh, not with the traffic —
                # unlike Ryu, where a reactive rule's duration is its idle lifetime. The
                # deployed model uses mean_flow_duration as a discriminating feature, so
                # this is the main accuracy gap between the two controllers and is
                # reported rather than papered over.
                duration = f["duration"]
                records.append(FlowRecord(dpid, src, dst, proto, sport, dport,
                                          f["packets"], f["bytes"], duration))
        windows = self.extractor.compute(records)
        if self._baseline_rounds > 0:
            # The forwarding mesh exists before the engine starts, so the first round finds
            # only "old" rules and reports zero deltas (the pre-existing-rule guard). One
            # extra round establishes the baseline; after that, deltas are real.
            self._baseline_rounds -= 1
            return {}
        self.poll_ms.append((time.perf_counter() - t0) * 1e3)

        now = time.time()
        hosts = {}
        for src, w in windows.items():
            feats = w["features"]
            if feats["pkt_rate"] <= 0 and feats["new_flows"] == 0:
                continue
            label, prob = "idle", None
            if self.detector is not None and feats["pkt_rate"] >= C.MIN_PKT_RATE:
                label, prob = self._analyse(now, src, w["dpid"], feats)
            hosts[src] = {"pkt_rate": round(feats["pkt_rate"], 1),
                          "byte_rate": round(feats["byte_rate"], 1),
                          "label": label, "prob": prob}
        for ip in self.engine.active:
            hosts.setdefault(ip, {"pkt_rate": 0.0, "byte_rate": 0.0, "label": "idle", "prob": None})
        for ip, h in hosts.items():
            h["state"] = self.engine.current_action(ip, now)
        with self.lock:
            self.rounds.append({"ts": round(now, 3), "mode": self.mode, "hosts": hosts,
                                "flows": {}, "controller": "odl"})
        return hosts

    def _analyse(self, now, src, dpid, feats):
        label, prob, probs, x = self.detector.predict(feats)
        if label == "benign":
            self.engine.decide(src, label, prob, [], now)
            return label, round(prob, 4)
        top = self.explainer.explain(x, label, C.TOP_K)
        action, gates, reason = self.engine.decide(src, label, prob, top, now)
        if self.mode == "monitor" and action in (RATE_LIMIT, BLOCK):
            reason, action = f"monitor mode (would {action})", ALERT
        if action in (RATE_LIMIT, BLOCK):
            self._mitigate(src, action)
        entry = {"ts": now, "src_ip": src, "dpid": dpid, "label": label,
                 "confidence": round(prob, 4), "probs": {k: round(v, 4) for k, v in probs.items()},
                 "explanation": top, "gates": gates, "action": action, "reason": reason,
                 "active": self.engine.current_action(src, now), "controller": "odl"}
        with self.lock:
            self.decisions.append(entry)
        return label, round(prob, 4)

    # ------------------------------------------------------------------ response
    def _mitigate(self, src, action):
        """ODL counterpart of the Ryu mitigator: a high-priority DROP in the security table.
        ODL 0.24.1 has no meter RPC exposed over RESTCONF, so RATE_LIMIT degrades to a DROP
        with a longer timeout and the audit log records that substitution."""
        timeout = C.BLOCK_HARD_TIMEOUT if action == BLOCK else C.LIMIT_HARD_TIMEOUT
        for node in self.nodes:
            try:
                self.odl.drop_source(node, src, priority=MITIGATION_PRIORITY,
                                     hard_timeout=timeout, name=f"xai-drop-{src}-{node}")
            except ODLError as e:
                print(f"[odl] mitigation on {node} failed: {e}")
        self.mitigations[src] = {"action": action, "expires": time.time() + timeout}

    def release(self, src):
        for node in self.nodes:
            match = ODL.build_match(ipv4_src=src)
            try:
                self.odl.remove_flow(node, match, priority=MITIGATION_PRIORITY,
                                     name=f"xai-drop-{src}-{node}")
            except ODLError:
                pass
        self.engine.active.pop(src, None)
        self.mitigations.pop(src, None)


# ---------------------------------------------------------------------- REST for the dashboard
class _Handler(BaseHTTPRequestHandler):
    engine = None

    def log_message(self, *args):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        e = self.engine
        if self.path.startswith("/xai/rounds"):
            with e.lock:
                return self._json({"rounds": list(e.rounds)})
        if self.path.startswith("/xai/decisions"):
            with e.lock:
                return self._json({"decisions": list(e.decisions)})
        if self.path.startswith("/xai/mitigations"):
            return self._json({"mitigations": [
                {"src": ip, "action": m["action"], "expires": m["expires"]}
                for ip, m in e.mitigations.items()]})
        if self.path.startswith("/xai/status"):
            return self._json({"controller": "odl", "mode": e.mode, "nodes": e.nodes,
                               "poll_interval": e.interval,
                               "poll_ms_avg": round(sum(e.poll_ms) / len(e.poll_ms), 1) if e.poll_ms else None,
                               "switches": len(e.nodes)})
        if self.path.startswith("/xai/alerts"):
            with e.lock:
                return self._json({"alerts": [d for d in e.decisions if d["action"] != NONE][-100:]})
        self._json({"error": "not found"}, 404)

    def do_DELETE(self):
        if self.path.startswith("/xai/mitigations/"):
            ip = self.path.rsplit("/", 1)[-1]
            self.engine.release(ip)
            return self._json({"released": ip})
        self._json({"error": "not found"}, 404)


def serve(engine, port=8080):
    handler = type("H", (_Handler,), {"engine": engine})
    srv = ThreadingHTTPServer(("0.0.0.0", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    ap = argparse.ArgumentParser(description="XAI-IDS on OpenDaylight")
    ap.add_argument("--odl", default=os.environ.get("ODL_URL", "http://127.0.0.1:8182"))
    ap.add_argument("--user", default=os.environ.get("ODL_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("ODL_PASSWORD", "admin"))
    ap.add_argument("--mode", default=os.environ.get("XAI_IDS_MODE", "detect"),
                    choices=["collect", "monitor", "detect"])
    ap.add_argument("--duration", type=float, default=0, help="seconds to run (0 = forever)")
    ap.add_argument("--api-port", type=int, default=8080)
    ap.add_argument("--provision", action="store_true",
                    help="install the L3 forwarding mesh first (slow: ~0.5 s per rule)")
    args = ap.parse_args()

    eng = ODLIdsEngine(args.odl, args.user, args.password, args.mode)
    print(f"[odl] nodes: {eng.refresh_nodes()}")
    if args.provision:
        eng.provision()
    serve(eng, args.api_port)
    start = time.time()
    while not args.duration or time.time() - start < args.duration:
        t0 = time.time()
        try:
            eng.poll_once()
        except ODLError as e:
            print(f"[odl] poll failed: {e}")
        time.sleep(max(0.0, eng.interval - (time.time() - t0)))


if __name__ == "__main__":
    main()
