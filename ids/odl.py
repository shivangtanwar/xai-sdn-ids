"""OpenDaylight RESTCONF client: inventory, per-flow statistics and flow programming.

ODL 0.24.1 serves RESTCONF on its *Netty* endpoint (:8182/restconf), not the old
Karaf/Pax-Web one on :8181. Flow programming goes through the MD-SAL RPCs
`sal-flow:add-flow` / `sal-flow:remove-flow`; the inventory model is read-only in
this build, so PUT on /restconf/data/... is not an option.

Authentication is ODL's built-in AAA (admin/admin by default).

    odl = ODL("http://127.0.0.1:8182", "admin", "admin")
    odl.add_flow("openflow:1", priority=100, match={"ipv4-source": "10.0.0.1/32"}, out_port=2)
    for f in odl.flow_stats("openflow:1"):
        ...
"""
import json
import urllib.error
import urllib.request

ETH_IPV4 = 2048


def _node_uri(node):
    """RESTCONF instance identifier for one node, e.g. /opendaylight-inventory:nodes/...
    odl-inventory:node[opendaylight-inventory:id="openflow:1"]"""
    return ('/opendaylight-inventory:nodes/opendaylight-inventory:node'
            f'[opendaylight-inventory:id="{node}"]')


class ODLError(RuntimeError):
    pass


class ODL:
    def __init__(self, base="http://127.0.0.1:8182", user="admin", password="admin", timeout=10):
        self.base = base.rstrip("/")
        self.auth = (user, password)
        self.timeout = timeout

    # ------------------------------------------------------------------ plumbing
    def _request(self, method, path, body=None, accept="application/json"):
        url = f"{self.base}/{path.lstrip('/')}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", accept)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        import base64
        token = base64.b64encode(f"{self.auth[0]}:{self.auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                payload = r.read()
                return r.status, (json.loads(payload) if payload.strip() else None)
        except urllib.error.HTTPError as e:
            raise ODLError(f"{method} {url} -> HTTP {e.code}: {e.read()[:300]!r}") from None
        except urllib.error.URLError as e:
            raise ODLError(f"{method} {url} -> {e.reason}") from None

    # ------------------------------------------------------------------ inventory
    def nodes(self):
        """Switch ids known to ODL, e.g. ['openflow:1', 'openflow:2']."""
        _, d = self._request("GET", "restconf/data/opendaylight-inventory:nodes")
        return [n["id"] for n in d["opendaylight-inventory:nodes"]["node"]]

    def ports(self, node):
        """{port_number: port_name} for one switch (e.g. {2: 's2-eth2'})."""
        _, d = self._request("GET", f"restconf/data/opendaylight-inventory:nodes/node={node}?content=nonconfig")
        n = d["opendaylight-inventory:node"][0]
        out = {}
        for c in n.get("node-connector", []):
            tail = c["id"].rsplit(":", 1)[-1]
            if not tail.isdigit():            # the LOCAL connector
                continue
            out[int(tail)] = c.get("flow-node-inventory:name", c["id"])
        return out

    # ------------------------------------------------------------------ statistics
    def flow_stats(self, node, table=0):
        """Flow entries with counters from one switch.

        Returns [{"match": {...}, "packets": int, "bytes": int, "duration": float,
                  "priority": int, "id": str}]."""
        _, d = self._request("GET", f"restconf/data/opendaylight-inventory:nodes/node={node}?content=nonconfig")
        n = d["opendaylight-inventory:node"][0]
        out = []
        for t in n.get("flow-node-inventory:table", []):
            if int(t["id"]) != table:
                continue
            for f in t.get("flow", []):
                st = f.get("opendaylight-flow-statistics:flow-statistics", {})
                dur = st.get("duration", {})
                out.append({
                    "id": f.get("id"),
                    "priority": int(f.get("priority", 0)),
                    "match": f.get("match", {}),
                    "packets": int(st.get("packet-count", 0)),
                    "bytes": int(st.get("byte-count", 0)),
                    "duration": float(dur.get("second", 0)) + float(dur.get("nanosecond", 0)) / 1e9,
                })
        return out

    # ------------------------------------------------------------------ programming
    @staticmethod
    def build_match(ipv4_src=None, ipv4_dst=None, proto=None, service_port=None):
        """ODL JSON match. `service_port` is a destination L4 port (see _flow_match in the
        Ryu app: both controllers match the lower of the two L4 ports)."""
        m = {"ethernet-match": {"ethernet-type": {"type": ETH_IPV4}}}
        if ipv4_src:
            m["ipv4-source"] = ipv4_src if "/" in ipv4_src else ipv4_src + "/32"
        if ipv4_dst:
            m["ipv4-destination"] = ipv4_dst if "/" in ipv4_dst else ipv4_dst + "/32"
        if proto:
            m["ip-match"] = {"ip-protocol": proto}
            if service_port and proto == 6:
                m["tcp-match"] = {"tcp-destination-port": service_port}
            elif service_port and proto == 17:
                m["udp-match"] = {"udp-destination-port": service_port}
        return m

    def add_flow(self, node, match, out_port=None, priority=100, table=0, name=None,
                 idle_timeout=0, hard_timeout=0):
        """Install one flow. `out_port=None` installs an empty instruction list = DROP."""
        instructions = {"instruction": []}
        if out_port is not None:
            instructions = {"instruction": [{"order": 0, "apply-actions": {"action": [
                {"order": 0, "output-action": {"output-node-connector": str(out_port)}}]}}]}
        body = {"input": {
            "node": _node_uri(node),
            "table_id": table,
            "priority": priority,
            "flow-name": name or f"xai-{priority}",
            "match": match,
            "instructions": instructions,
            "idle-timeout": idle_timeout,
            "hard-timeout": hard_timeout,
        }}
        self._request("POST", "restconf/operations/sal-flow:add-flow", body)
        return name

    def remove_flow(self, node, match, priority=100, table=0, name=None):
        body = {"input": {"node": _node_uri(node), "table_id": table, "priority": priority,
                          "flow-name": name or f"xai-{priority}", "match": match}}
        self._request("POST", "restconf/operations/sal-flow:remove-flow", body)

    def drop_source(self, node, ip, priority=1000, hard_timeout=60, name=None):
        """Security-table DROP for one source IP (the ODL counterpart of the Ryu mitigator)."""
        return self.add_flow(node, self.build_match(ipv4_src=ip), out_port=None,
                             priority=priority, hard_timeout=hard_timeout,
                             name=name or f"xai-drop-{ip}")
