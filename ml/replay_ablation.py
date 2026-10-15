#!/usr/bin/env python3
"""Offline ablation of the Confidence-Gated Response Engine.

Replays a recorded session (raw feature log + ground truth) through the deployed model,
the SHAP explainer and several engine configurations, in timestamp order exactly as the
controller would see it. In a replay, mitigation does not stop the attack traffic, so we
count *decisions*:
  - benign impairment: seconds a non-attacking source spent rate-limited/blocked, and how
    many distinct benign sources were hit
  - attacks mitigated: attack episodes with at least one RATE_LIMIT/BLOCK
  - time to mitigate:  episode start -> first mitigation decision

    python3 ml/replay_ablation.py test2
"""
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ids import config as C  # noqa: E402
from ids.detector import Detector  # noqa: E402
from ids.explainer import Explainer  # noqa: E402
from ids.policy import ResponseEngine  # noqa: E402
from ml.plotstyle import INK_2, SERIES, plt  # noqa: E402

VARIANTS = {
    "Naive (block on label)": (),
    "G1 confidence": ("G1",),
    "G1+G2 persistence": ("G1", "G2"),
    "Full CGRE (G1-G4)": ("G1", "G2", "G3", "G4"),
}


def ground_truth(feats, labels):
    feats = feats.copy()
    feats["truth"], feats["episode"] = "benign", -1
    for i, ep in enumerate(labels.itertuples()):
        if ep.label == "heavy_benign":
            continue
        # a row logged at ts describes traffic up to ~2 polling intervals earlier
        m = (feats.src_ip == ep.src_ip) & (feats.ts > ep.start) & (feats.ts <= ep.end + 2 * C.POLL_INTERVAL + 0.5)
        feats.loc[m, ["truth", "episode"]] = [ep.label, i]
    return feats


def main():
    run = sys.argv[1] if len(sys.argv) > 1 else "test2"
    feats = pd.read_csv(os.path.join(C.ROOT, "data", "raw", f"features_{run}.csv")).sort_values("ts")
    labels = pd.read_csv(os.path.join(C.ROOT, "data", "raw", f"labels_{run}.csv"))
    feats = ground_truth(feats, labels)
    attacks = labels[labels.label != "heavy_benign"].reset_index()

    det = Detector()
    expl = Explainer(det)
    scored = []
    for row in feats.itertuples(index=False):
        f = {k: getattr(row, k) for k in C.FEATURES}
        if f["pkt_rate"] < C.MIN_PKT_RATE:
            continue
        label, p, _, x = det.predict(f)
        top = expl.explain(x, label, C.TOP_K) if label != "benign" else []
        scored.append((row.ts, row.src_ip, row.truth, row.episode, label, p, top))

    rows = []
    for name, gates in VARIANTS.items():
        eng = ResponseEngine(gates=gates)
        impaired_windows, victims, hit = 0, set(), {}
        for ts, src, truth, ep, label, p, top in scored:
            action = eng.decide(src, label, p, top, now=ts)[0]
            active = eng.current_action(src, ts) in ("RATE_LIMIT", "BLOCK")
            if truth == "benign" and active:
                impaired_windows += 1
                victims.add(src)
            # an attack counts as mitigated once its source is under an active mitigation
            # (a new decision, or one still active from an earlier episode)
            if truth != "benign" and active and ep not in hit:
                hit[int(ep)] = ts
        ttm = [hit[i] - attacks.loc[attacks["index"] == i, "start"].iloc[0] for i in hit]
        rows.append({"variant": name,
                     "benign_impaired_s": impaired_windows * C.POLL_INTERVAL,
                     "benign_sources_hit": len(victims),
                     "sources": " ".join(sorted(victims)),
                     "attacks_mitigated": f"{len(hit)}/{len(attacks)}",
                     "mean_time_to_mitigate_s": round(sum(ttm) / len(ttm), 2) if ttm else None})
    out = pd.DataFrame(rows)
    print(out.to_string(index=False))
    out.to_csv(os.path.join(C.ROOT, "results", f"ablation_{run}.csv"), index=False)

    fig, ax = plt.subplots(figsize=(6.4, 3.0))
    y = list(range(len(out)))[::-1]
    ax.barh(y, out["benign_impaired_s"], color=SERIES[0], height=0.6)
    ax.set_yticks(y)
    ax.set_yticklabels(out["variant"])
    ax.grid(axis="y", visible=False)
    for yi, v, a, t in zip(y, out["benign_impaired_s"], out["attacks_mitigated"], out["mean_time_to_mitigate_s"]):
        ax.text(v + 1, yi, f"{v:.0f} s   (attacks mitigated {a}, mean {t} s)", va="center", fontsize=8, color=INK_2)
    ax.set_xlim(0, max(out["benign_impaired_s"].max() * 2.2, 20))
    ax.set_xlabel("Seconds legitimate sources spent rate-limited / blocked")
    ax.set_title(f"Gating ablation (replay of held-out session {run})")
    fig.savefig(os.path.join(C.ROOT, "results", f"ablation_{run}.png"))
    plt.close(fig)


if __name__ == "__main__":
    main()
