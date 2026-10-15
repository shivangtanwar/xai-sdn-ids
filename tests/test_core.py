"""Unit tests for the feature extractor and the Confidence-Gated Response Engine.

    docker run --rm -v "$PWD":/app -w /app xai-sdn-ids/controller python -m unittest -v
"""
import unittest

from ids import config as C
from ids.features import FeatureExtractor, FlowRecord
from ids.policy import ALERT, BLOCK, NONE, RATE_LIMIT, ResponseEngine

SCAN_EXPL = [{"feature": "n_dst_ports", "value": 900, "shap": 0.4},
             {"feature": "new_flows", "value": 450, "shap": 0.2},
             {"feature": "frac_tcp", "value": 1.0, "shap": 0.05}]
ODD_EXPL = [{"feature": "mean_flow_duration", "value": 3, "shap": 0.4},
            {"feature": "frac_icmp", "value": 0, "shap": 0.2},
            {"feature": "n_dst_ips", "value": 1, "shap": 0.1}]


class FeatureExtractorTest(unittest.TestCase):
    def test_deltas_and_ingress_switch(self):
        fx = FeatureExtractor(interval=2.0)
        # round 1: one UDP flow seen on edge s2 (100 pkts) and core s1 (90 pkts)
        fx.compute([FlowRecord(2, "10.0.0.4", "10.0.0.5", 17, None, 53, 100, 10000, 1.0),
                    FlowRecord(1, "10.0.0.4", "10.0.0.5", 17, None, 53, 90, 9000, 1.0)])
        fx.count_packet_in("10.0.0.4")
        out = fx.compute([FlowRecord(2, "10.0.0.4", "10.0.0.5", 17, None, 53, 300, 30000, 3.0),
                          FlowRecord(1, "10.0.0.4", "10.0.0.5", 17, None, 53, 280, 28000, 3.0)])
        w = out["10.0.0.4"]
        self.assertEqual(w["dpid"], 2)                       # ingress switch wins
        self.assertAlmostEqual(w["features"]["pkt_rate"], 100.0)   # (300-100)/2
        self.assertAlmostEqual(w["features"]["avg_pkt_size"], 100.0)
        self.assertAlmostEqual(w["features"]["frac_udp"], 1.0)
        self.assertAlmostEqual(w["features"]["pktin_rate"], 0.5)
        self.assertEqual(w["features"]["new_flows"], 0)

    def test_scan_shape(self):
        fx = FeatureExtractor(interval=2.0)
        recs = [FlowRecord(2, "10.0.0.7", "10.0.0.6", 6, None, p, 1, 60, 0.1) for p in range(1, 201)]
        f = fx.compute(recs)["10.0.0.7"]["features"]
        self.assertEqual(f["n_dst_ports"], 200)
        self.assertEqual(f["new_flows"], 200)
        self.assertAlmostEqual(f["frac_small_flows"], 1.0)


class ResponseEngineTest(unittest.TestCase):
    def test_benign_never_mitigated(self):
        eng = ResponseEngine()
        self.assertEqual(eng.decide("10.0.0.1", "benign", 0.99, [], now=0)[0], NONE)

    def test_persistence_then_block(self):
        eng = ResponseEngine()
        self.assertEqual(eng.decide("10.0.0.7", "port_scan", 0.97, SCAN_EXPL, now=0)[0], ALERT)
        self.assertEqual(eng.decide("10.0.0.7", "port_scan", 0.97, SCAN_EXPL, now=2)[0], BLOCK)
        # already blocked: no duplicate rule until it expires
        self.assertEqual(eng.decide("10.0.0.7", "port_scan", 0.97, SCAN_EXPL, now=4)[0], NONE)
        self.assertEqual(eng.current_action("10.0.0.7", now=2 + C.BLOCK_HARD_TIMEOUT + 1), NONE)

    def test_medium_confidence_rate_limits(self):
        eng = ResponseEngine()
        eng.decide("10.0.0.4", "port_scan", 0.8, SCAN_EXPL, now=0)
        self.assertEqual(eng.decide("10.0.0.4", "port_scan", 0.8, SCAN_EXPL, now=2)[0], RATE_LIMIT)

    def test_inconsistent_explanation_only_alerts(self):
        eng = ResponseEngine()
        for t in range(3):
            action, gates, _ = eng.decide("10.0.0.4", "port_scan", 0.99, ODD_EXPL, now=t)
        self.assertEqual(action, ALERT)
        self.assertFalse(gates["G3"])

    def test_protected_asset_only_alerts(self):
        eng = ResponseEngine()
        for t in range(3):
            action = eng.decide("10.0.0.5", "syn_flood", 0.99, [{"feature": "pkt_rate"}], now=t)[0]
        self.assertEqual(action, ALERT)

    def test_low_confidence_ignored(self):
        eng = ResponseEngine()
        self.assertEqual(eng.decide("10.0.0.4", "udp_flood", 0.5, [{"feature": "pkt_rate"}], now=0)[0], NONE)

    def test_naive_baseline_blocks_immediately(self):
        eng = ResponseEngine(gates=())
        self.assertEqual(eng.decide("10.0.0.5", "syn_flood", 0.5, ODD_EXPL, now=0)[0], BLOCK)


if __name__ == "__main__":
    unittest.main()
