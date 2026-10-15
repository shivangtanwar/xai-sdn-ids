#!/usr/bin/env python3
"""Join controller feature logs with scenario ground truth.

A feature row at time ts summarises (ts - POLL_INTERVAL, ts]. It gets the episode's label
if that window lies inside an episode of the same source IP. Windows that only partly
overlap an episode (its ramp-up/ramp-down) are dropped as ambiguous. "heavy_benign"
episodes are labelled benign. Everything else is benign.

    python3 ml/build_dataset.py train1 test1
    -> data/processed/<run>.csv for every run
"""
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ids.config import FEATURES, POLL_INTERVAL, ROOT  # noqa: E402


def label_run(run):
    feats = pd.read_csv(os.path.join(ROOT, "data", "raw", f"features_{run}.csv"))
    labels = pd.read_csv(os.path.join(ROOT, "data", "raw", f"labels_{run}.csv"))
    feats["label"] = "benign"
    feats["scenario"] = "background"
    keep = pd.Series(True, index=feats.index)
    for ep in labels.itertuples():
        same_src = feats["src_ip"] == ep.src_ip
        w_start, w_end = feats["ts"] - POLL_INTERVAL, feats["ts"]
        inside = same_src & (w_start >= ep.start) & (w_end <= ep.end + 0.5)
        overlap = same_src & (w_end > ep.start) & (w_start < ep.end + POLL_INTERVAL) & ~inside
        feats.loc[inside, "label"] = "benign" if ep.label == "heavy_benign" else ep.label
        feats.loc[inside, "scenario"] = ep.label
        keep &= ~overlap
    out = feats[keep].copy()
    out["run"] = run
    return out[["ts", "run", "src_ip", "dpid", "scenario"] + FEATURES + ["label"]]


def main():
    runs = sys.argv[1:] or ["train1", "test1"]
    os.makedirs(os.path.join(ROOT, "data", "processed"), exist_ok=True)
    for run in runs:
        df = label_run(run)
        path = os.path.join(ROOT, "data", "processed", f"{run}.csv")
        df.to_csv(path, index=False)
        print(f"{run}: {len(df)} rows -> {path}")
        print(df["label"].value_counts().to_string(), "\n")


if __name__ == "__main__":
    main()
