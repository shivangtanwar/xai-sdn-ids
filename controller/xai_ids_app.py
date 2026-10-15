"""XAI-IDS Ryu application (OpenFlow 1.3).

Pipeline on every switch:
    table 0  SECURITY   - mitigation rules (DROP / meter) installed by the response engine,
                          default: goto table 1
    table 1  FORWARDING - reactive L2-learning + L3/L4 flow rules, table-miss -> controller

Every POLL_INTERVAL seconds the app pulls flow statistics from table 1 of every switch,
builds per-source features, and (depending on XAI_IDS_MODE):
    collect - only logs features (dataset creation)
    monitor - detects + explains, logs decisions, never touches the network
    detect  - full closed loop: detect -> explain -> confidence gates -> mitigate
"""
import csv
import json
import os
import time
from collections import defaultdict

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3
from webob import Response

from ids import config as C
from ids.features import FeatureExtractor, FlowRecord
from ids.policy import ALERT, BLOCK, NONE, RATE_LIMIT, ResponseEngine

SECURITY_TABLE, FORWARD_TABLE = 0, 1
APP_NAME = "xai_ids_app"


class XaiIdsApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mode = C.MODE
        self.datapaths = {}
        self.mac_to_port = defaultdict(dict)
        self.src_dpids = defaultdict(set)      # src ip -> switches it was seen on
        self.meter_ids = {}                    # src ip -> meter id
        self.stats_buffer = []
        self.extractor = FeatureExtractor(C.POLL_INTERVAL)
        self.engine = ResponseEngine()
        self.first_flag = {}                   # src -> ts of first malicious window
        self.recent = []                       # recent audit entries for the REST API

        self.detector = self.explainer = None
        if self.mode != "collect":
            from ids.detector import Detector
            from ids.explainer import Explainer
            self.detector = Detector()
            self.explainer = Explainer(self.detector)

        os.makedirs(os.path.dirname(C.FEATURE_LOG), exist_ok=True)
        os.makedirs(os.path.dirname(C.AUDIT_LOG), exist_ok=True)
        self._feature_file = open(C.FEATURE_LOG, "a", newline="")
        self._feature_csv = csv.writer(self._feature_file)
        if self._feature_file.tell() == 0:
            self._feature_csv.writerow(["ts", "src_ip", "dpid"] + C.FEATURES)

        kwargs["wsgi"].register(XaiIdsRestApi, {APP_NAME: self})
        self.logger.info("XAI-IDS started in %s mode", self.mode)
        self.poller = hub.spawn(self._poll_loop)

    # ------------------------------------------------------------------ switch setup
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        # table 0: default is "continue to forwarding"
        self._add_flow(dp, SECURITY_TABLE, 0, parser.OFPMatch(),
                       [parser.OFPInstructionGotoTable(FORWARD_TABLE)])
        # table 1: table-miss -> controller
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, FORWARD_TABLE, 0, parser.OFPMatch(),
                       [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)])

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("switch connected: s%d", dp.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    def _add_flow(self, dp, table, priority, match, inst, idle=0, hard=0):
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(datapath=dp, table_id=table, priority=priority,
                                      match=match, instructions=inst,
                                      idle_timeout=idle, hard_timeout=hard))

    # ------------------------------------------------------------------ forwarding
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.mac_to_port[dp.id][eth.src] = in_port
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is not None:
            self.extractor.count_packet_in(ip.src)
            self.src_dpids[ip.src].add(dp.id)
            if out_port != ofp.OFPP_FLOOD:
                match = self._flow_match(parser, pkt, ip)
                inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                self._add_flow(dp, FORWARD_TABLE, C.FORWARD_PRIORITY, match, inst,
                               idle=C.FLOW_IDLE_TIMEOUT)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=data))

    @staticmethod
    def _flow_match(parser, pkt, ip):
        """Match (src, dst, proto, service port). The service port is the lower of the two
        L4 ports, so random client/attacker source ports don't create one rule per packet."""
        fields = {"eth_type": ether_types.ETH_TYPE_IP, "ipv4_src": ip.src,
                  "ipv4_dst": ip.dst, "ip_proto": ip.proto}
        for proto, cls, name in ((6, tcp.tcp, "tcp"), (17, udp.udp, "udp")):
            l4 = pkt.get_protocol(cls)
            if ip.proto == proto and l4 is not None:
                if l4.src_port < l4.dst_port:
                    fields[name + "_src"] = l4.src_port
                else:
                    fields[name + "_dst"] = l4.dst_port
        return parser.OFPMatch(**fields)

    # ------------------------------------------------------------------ statistics
    def _poll_loop(self):
        while True:
            hub.sleep(C.POLL_INTERVAL)
            try:
                self._process_round()
            except Exception:  # never let one bad round kill the poller
                self.logger.exception("processing round failed")
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                dp.send_msg(parser.OFPFlowStatsRequest(dp, table_id=FORWARD_TABLE))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        for stat in ev.msg.body:
            if stat.priority != C.FORWARD_PRIORITY:
                continue
            m = stat.match
            src = m.get("ipv4_src")
            if src is None:
                continue
            self.stats_buffer.append(FlowRecord(
                dpid, src, m.get("ipv4_dst"), m.get("ip_proto"),
                m.get("tcp_src", m.get("udp_src")), m.get("tcp_dst", m.get("udp_dst")),
                stat.packet_count, stat.byte_count,
                stat.duration_sec + stat.duration_nsec / 1e9))

    def _process_round(self):
        records, self.stats_buffer = self.stats_buffer, []
        now = time.time()
        windows = self.extractor.compute(records)
        for src, w in windows.items():
            feats = w["features"]
            if feats["pkt_rate"] <= 0 and feats["new_flows"] == 0:
                continue
            self._feature_csv.writerow([f"{now:.3f}", src, w["dpid"]] +
                                       [f"{feats[f]:.4f}" for f in C.FEATURES])
            if self.detector is not None and feats["pkt_rate"] >= C.MIN_PKT_RATE:
                self._analyse(now, src, w["dpid"], feats)
        self._feature_file.flush()

    # ------------------------------------------------------------------ detection
    def _analyse(self, now, src, dpid, feats):
        t0 = time.perf_counter()
        label, prob, probs, x = self.detector.predict(feats)
        t_pred = time.perf_counter()
        if label == "benign":
            self.engine.decide(src, label, prob, [], now)
            self.first_flag.pop(src, None)
            return
        top = self.explainer.explain(x, label, C.TOP_K)
        t_expl = time.perf_counter()
        self.first_flag.setdefault(src, now)

        action, gates, reason = self.engine.decide(src, label, prob, top, now)
        if self.mode == "monitor" and action in (RATE_LIMIT, BLOCK):
            reason = f"monitor mode (would {action})"
            action = ALERT
        t_mit = None
        if action in (RATE_LIMIT, BLOCK):
            self._mitigate(src, action)
            t_mit = time.time()

        entry = {
            "ts": now, "src_ip": src, "dpid": dpid, "label": label,
            "confidence": round(prob, 4), "probs": {k: round(v, 4) for k, v in probs.items()},
            "explanation": top, "gates": gates, "action": action, "reason": reason,
            "active": self.engine.current_action(src, now),
            "infer_ms": round((t_pred - t0) * 1e3, 3),
            "explain_ms": round((t_expl - t_pred) * 1e3, 3),
            "first_flag_ts": self.first_flag[src],
            "mitigation_ts": t_mit,
        }
        self._audit(entry)

    def _audit(self, entry):
        with open(C.AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
        self.recent = (self.recent + [entry])[-200:]
        if entry["action"] != NONE:
            why = ", ".join(f"{e['feature']}={e['value']:.1f}" for e in entry["explanation"])
            self.logger.warning("[%s] %s -> %s (p=%.2f) because %s | %s",
                                entry["action"], entry["src_ip"], entry["label"],
                                entry["confidence"], why, entry["reason"])

    # ------------------------------------------------------------------ mitigation
    def _mitigate(self, src, action):
        for dpid in self.src_dpids.get(src, ()):
            dp = self.datapaths.get(dpid)
            if dp is None:
                continue
            parser, ofp = dp.ofproto_parser, dp.ofproto
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src)
            if action == BLOCK:
                # empty instruction list = drop
                self._add_flow(dp, SECURITY_TABLE, C.MITIGATION_PRIORITY, match, [],
                               hard=C.BLOCK_HARD_TIMEOUT)
            else:
                meter_id = self.meter_ids.setdefault(src, len(self.meter_ids) + 1)
                band = parser.OFPMeterBandDrop(rate=C.RATE_LIMIT_KBPS, burst_size=C.RATE_LIMIT_KBPS // 10)
                dp.send_msg(parser.OFPMeterMod(dp, command=ofp.OFPMC_ADD, flags=ofp.OFPMF_KBPS,
                                               meter_id=meter_id, bands=[band]))
                inst = [parser.OFPInstructionMeter(meter_id, ofp.OFPIT_METER),
                        parser.OFPInstructionGotoTable(FORWARD_TABLE)]
                self._add_flow(dp, SECURITY_TABLE, C.MITIGATION_PRIORITY - 100, match, inst,
                               hard=C.LIMIT_HARD_TIMEOUT)

    def release(self, src):
        """Manually lift a mitigation (operator override via REST)."""
        for dpid in self.src_dpids.get(src, ()):
            dp = self.datapaths.get(dpid)
            if dp is None:
                continue
            parser, ofp = dp.ofproto_parser, dp.ofproto
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src)
            dp.send_msg(parser.OFPFlowMod(datapath=dp, table_id=SECURITY_TABLE,
                                          command=ofp.OFPFC_DELETE, out_port=ofp.OFPP_ANY,
                                          out_group=ofp.OFPG_ANY, match=match))
        self.engine.active.pop(src, None)


class XaiIdsRestApi(ControllerBase):
    """GET  /xai/alerts             recent decisions with explanations
       GET  /xai/mitigations        currently active mitigations
       DELETE /xai/mitigations/{ip} operator override: release a source"""

    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data[APP_NAME]

    @staticmethod
    def _json(obj, status=200):
        return Response(status=status, content_type="application/json", charset="utf-8",
                        body=json.dumps(obj, indent=2))

    @route("xai", "/xai/alerts", methods=["GET"])
    def alerts(self, req, **kwargs):
        return self._json([e for e in self.app.recent if e["action"] != NONE][-50:])

    @route("xai", "/xai/mitigations", methods=["GET"])
    def mitigations(self, req, **kwargs):
        now = time.time()
        return self._json({src: {"action": a, "expires_in": round(exp - now, 1)}
                           for src, (a, exp) in self.app.engine.active.items() if exp > now})

    @route("xai", "/xai/mitigations/{ip}", methods=["DELETE"])
    def release(self, req, ip, **kwargs):
        self.app.release(ip)
        return self._json({"released": ip})
