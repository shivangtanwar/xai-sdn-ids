"""Turn raw OpenFlow flow statistics into per-source, time-windowed features.

Each poll gives cumulative packet/byte counters for every flow entry. We keep the previous
counters per (dpid, flow key) to compute deltas, then aggregate per source IP. A source's
traffic is counted on every switch it traverses, so per source we keep the switch that saw
the most packets (its ingress edge switch) to avoid double counting.
"""
from collections import defaultdict

from ids.config import FEATURES

IP_PROTO = {1: "icmp", 6: "tcp", 17: "udp"}


class FlowRecord:
    """One forwarding flow entry. Rules match a single L4 *service* port: either the
    destination port (requests) or the source port (replies), the other one is None."""
    __slots__ = ("dpid", "src", "dst", "proto", "sport", "dport", "packets", "bytes", "duration")

    def __init__(self, dpid, src, dst, proto, sport, dport, packets, bytes_, duration):
        self.dpid, self.src, self.dst = dpid, src, dst
        self.proto, self.sport, self.dport = proto, sport, dport
        self.packets, self.bytes, self.duration = packets, bytes_, duration

    @property
    def key(self):
        return (self.dpid, self.src, self.dst, self.proto, self.sport, self.dport)


class FeatureExtractor:
    def __init__(self, interval):
        self.interval = interval
        self._prev = {}          # flow key -> (packets, bytes)
        self._pktin = defaultdict(int)

    def count_packet_in(self, src_ip):
        self._pktin[src_ip] += 1

    def compute(self, records):
        """records: FlowRecords from one polling round (all switches).

        Returns {src_ip: {"dpid": ..., "features": {...}}}.
        """
        per_switch = defaultdict(list)   # (src, dpid) -> [(record, dpkts, dbytes, is_new)]
        current = {}
        for r in records:
            prev = self._prev.get(r.key)
            is_new = prev is None
            dp = r.packets - (prev[0] if prev else 0)
            db = r.bytes - (prev[1] if prev else 0)
            if dp < 0:   # flow was re-installed and counters reset
                dp, db, is_new = r.packets, r.bytes, True
            current[r.key] = (r.packets, r.bytes)
            per_switch[(r.src, r.dpid)].append((r, dp, db, is_new))
        self._prev = current

        best = {}
        for (src, dpid), rows in per_switch.items():
            total = sum(row[1] for row in rows)
            if src not in best or total > best[src][0]:
                best[src] = (total, dpid, rows)

        pktin, self._pktin = self._pktin, defaultdict(int)
        out = {}
        for src, (_total, dpid, rows) in best.items():
            out[src] = {"dpid": dpid, "features": self._aggregate(rows, pktin.get(src, 0))}
        return out

    def _aggregate(self, rows, pktin_count):
        t = self.interval
        dpkts = sum(r[1] for r in rows)
        dbytes = sum(r[2] for r in rows)
        proto_pkts = defaultdict(int)
        for rec, dp, _db, _new in rows:
            proto_pkts[IP_PROTO.get(rec.proto, "other")] += dp
        n_flows = len(rows)
        f = {
            "pkt_rate": dpkts / t,
            "byte_rate": dbytes / t,
            "avg_pkt_size": dbytes / dpkts if dpkts else 0.0,
            "n_flows": n_flows,
            "new_flows": sum(1 for r in rows if r[3]),
            "n_dst_ips": len({r[0].dst for r in rows}),
            "n_dst_ports": len({(r[0].dst, r[0].dport) for r in rows if r[0].dport is not None}),
            "frac_tcp": proto_pkts["tcp"] / dpkts if dpkts else 0.0,
            "frac_udp": proto_pkts["udp"] / dpkts if dpkts else 0.0,
            "frac_icmp": proto_pkts["icmp"] / dpkts if dpkts else 0.0,
            "pkts_per_flow": dpkts / n_flows if n_flows else 0.0,
            "frac_small_flows": sum(1 for r in rows if r[0].packets <= 2) / n_flows if n_flows else 0.0,
            "mean_flow_duration": sum(r[0].duration for r in rows) / n_flows if n_flows else 0.0,
            "pktin_rate": pktin_count / t,
        }
        return {k: float(f[k]) for k in FEATURES}
