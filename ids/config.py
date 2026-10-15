"""Central configuration for the XAI-IDS pipeline and the Confidence-Gated Response Engine."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Operating mode: collect = log features only, monitor = detect + explain but never
# mitigate, detect = full closed loop.
MODE = os.environ.get("XAI_IDS_MODE", "detect")

POLL_INTERVAL = 2.0          # seconds between OFPFlowStatsRequests
FLOW_IDLE_TIMEOUT = 10       # reactive forwarding rules
FORWARD_PRIORITY = 10
MITIGATION_PRIORITY = 1000

CLASSES = ["benign", "icmp_flood", "syn_flood", "udp_flood", "port_scan"]

FEATURES = [
    "pkt_rate", "byte_rate", "avg_pkt_size",
    "n_flows", "new_flows", "n_dst_ips", "n_dst_ports",
    "frac_tcp", "frac_udp", "frac_icmp",
    "pkts_per_flow", "frac_small_flows", "mean_flow_duration",
    "pktin_rate",
]

MODEL_PATH = os.path.join(ROOT, "models", "rf_model.joblib")
FEATURE_LOG = os.environ.get("XAI_FEATURE_LOG", os.path.join(ROOT, "data", "raw", "features_live.csv"))
AUDIT_LOG = os.path.join(ROOT, "results", "audit_log.jsonl")

# --- Confidence-Gated Response Engine ------------------------------------------------
TAU_BLOCK = 0.90             # G1: probability needed to BLOCK
TAU_LIMIT = 0.70             # G1: probability needed to RATE_LIMIT / ALERT
PERSIST_K, PERSIST_N = 2, 3  # G2: flagged in >= k of last n windows
TOP_K = 3                    # G3: how many top SHAP features are checked
BLOCK_HARD_TIMEOUT = 60      # seconds; DROP auto-expires and is re-evaluated
LIMIT_HARD_TIMEOUT = 60
RATE_LIMIT_KBPS = 1000
MIN_PKT_RATE = 5.0           # ignore near-idle sources entirely

# G3: features that should plausibly drive each attack class.
SIGNATURES = {
    "icmp_flood": {"pkt_rate", "byte_rate", "frac_icmp", "avg_pkt_size", "pkts_per_flow"},
    "syn_flood": {"pkt_rate", "byte_rate", "frac_tcp", "avg_pkt_size", "pkts_per_flow", "pktin_rate"},
    "udp_flood": {"pkt_rate", "byte_rate", "frac_udp", "avg_pkt_size", "pkts_per_flow"},
    "port_scan": {"n_dst_ports", "new_flows", "n_flows", "frac_small_flows", "pkts_per_flow", "pktin_rate"},
}

# G4: never mitigate these sources automatically (alert only).
PROTECTED_IPS = {"10.0.0.5", "10.0.0.6"}
