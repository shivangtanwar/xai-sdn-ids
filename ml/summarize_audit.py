#!/usr/bin/env python3
"""Summarise results/audit_log.jsonl against the scenario ground truth.

Prints each mitigation with its explanation, and per-episode detection/mitigation latency
(episode start -> first flag, episode start -> rule installed).

    python3 ml/summarize_audit.py [--labels data/raw/labels_demo.csv]
"""
import argparse
import json
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ids.config import AUDIT_LOG, ROOT  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", default=os.path.join(ROOT, "data", "raw", "labels_demo.csv"))
    args = ap.parse_args()

    entries = [json.loads(line) for line in open(AUDIT_LOG)]
    acted = [e for e in entries if e["action"] != "NONE"]
    for e in acted:
        why = ", ".join(f"{x['feature']}={x['value']:.1f} ({x['shap']:+.2f})" for x in e["explanation"])
        print(f"{e['ts']:.0f} {e['src_ip']:<10} {e['action']:<10} {e['label']:<11} p={e['confidence']:.2f} "
              f"| {why} | {e['reason']}")

    if not os.path.exists(args.labels):
        return
    rows = []
    for ep in pd.read_csv(args.labels).itertuples():
        mine = [e for e in entries if e["src_ip"] == ep.src_ip and ep.start <= e["ts"] <= ep.end + 4]
        flagged = [e for e in mine if e["label"] != "benign"]
        mitig = [e for e in mine if e["action"] in ("BLOCK", "RATE_LIMIT")]
        rows.append({
            "episode": ep.label, "src": ep.src_ip,
            "first_flag_s": round(flagged[0]["ts"] - ep.start, 2) if flagged else None,
            "mitigated_s": round(mitig[0]["mitigation_ts"] - ep.start, 2) if mitig else None,
            "action": mitig[0]["action"] if mitig else "none",
            "infer_ms": round(sum(e["infer_ms"] for e in mine) / len(mine), 2) if mine else None,
            "explain_ms": round(sum(e["explain_ms"] for e in flagged) / len(flagged), 2) if flagged else None,
        })
    print("\n" + pd.DataFrame(rows).to_string(index=False))


if __name__ == "__main__":
    main()
