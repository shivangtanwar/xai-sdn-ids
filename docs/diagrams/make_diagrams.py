#!/usr/bin/env python3
"""Render the design diagrams (architecture, topology, CGRE flow, ML pipeline) to PNG.

    docker run --rm -v "$PWD":/app -w /app xai-sdn-ids/controller python docs/diagrams/make_diagrams.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

from ml.plotstyle import INK, INK_2, SERIES, SURFACE, plt  # noqa: E402

OUT = os.path.dirname(os.path.abspath(__file__))
BLUE, ORANGE, AQUA, YELLOW, VIOLET = SERIES[0], SERIES[1], SERIES[2], SERIES[3], SERIES[6]
TINT = {BLUE: "#e6f0fc", ORANGE: "#fde9e0", AQUA: "#e0f5ec", YELLOW: "#fdf1d6", VIOLET: "#eae7f7",
        "gray": "#f0efec"}


def canvas(w, h):
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, w)
    ax.set_ylim(0, h)
    ax.axis("off")
    return fig, ax


def box(ax, x, y, w, h, text, color=BLUE, fill=None, size=9, bold=False, radius=0.08):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={radius}",
                                facecolor=fill or TINT.get(color, SURFACE), edgecolor=color, linewidth=1.5))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=size, color=INK,
            fontweight="bold" if bold else "normal", linespacing=1.3)


def arrow(ax, x1, y1, x2, y2, text=None, color=INK_2, style="-|>", ls="-", tx=0, ty=0, size=8, rad=0.0):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=12, color=color,
                                 linewidth=1.4, linestyle=ls, connectionstyle=f"arc3,rad={rad}"))
    if text:
        ax.text((x1 + x2) / 2 + tx, (y1 + y2) / 2 + ty, text, fontsize=size, color=INK_2,
                ha="center", va="center", backgroundcolor=SURFACE)


def band(ax, y, h, label, color):
    ax.add_patch(FancyBboxPatch((0.2, y), 15.6, h, boxstyle="round,pad=0,rounding_size=0.12",
                                facecolor=TINT[color], edgecolor="none", alpha=0.55))
    ax.text(0.45, y + h - 0.28, label, fontsize=10, fontweight="bold", color=color, va="top")


def architecture():
    fig, ax = canvas(16, 10)
    band(ax, 6.55, 3.25, "APPLICATION PLANE: XAI-IDS engine", BLUE)
    band(ax, 3.55, 2.6, "CONTROL PLANE: Ryu controller (OpenFlow 1.3)", VIOLET)
    band(ax, 0.2, 3.0, "DATA PLANE: Mininet + Open vSwitch", AQUA)

    # application plane
    y = 8.0
    box(ax, 0.6, y, 2.9, 1.05, "Feature Extractor\n14 per-source features\n(2 s windows)", BLUE)
    box(ax, 4.3, y, 2.9, 1.05, "ML Detector\nRandomForest, 5 classes\nP(class | window)", BLUE)
    box(ax, 8.0, y, 2.9, 1.05, "SHAP Explainer\nTreeSHAP, top-k\nfeature contributions", BLUE)
    box(ax, 11.7, y, 3.8, 1.05, "Confidence-Gated Response\nEngine (CGRE)\nG1 conf · G2 persist · G3 XAI · G4 asset", BLUE, bold=True)
    for x1, x2 in ((3.5, 4.3), (7.2, 8.0), (10.9, 11.7)):
        arrow(ax, x1, y + 0.52, x2, y + 0.52)
    box(ax, 8.0, 6.8, 2.9, 0.75, "Audit log (JSONL)\np, gates, SHAP per decision", YELLOW, size=8)
    box(ax, 4.3, 6.8, 2.9, 0.75, "Operator dashboard\n(human-in-the-loop)", YELLOW, size=8)
    arrow(ax, 12.2, y, 10.9, 7.4)
    arrow(ax, 8.0, 7.17, 7.2, 7.17)

    # control plane
    y = 4.05
    box(ax, 0.6, y, 3.2, 1.2, "Stats Poller\nOFPFlowStatsRequest every 2 s\n+ Packet-In counter", VIOLET)
    box(ax, 4.3, y, 2.9, 1.2, "REST API (WSGI)\n/xai/alerts · /xai/mitigations\nDELETE = release", VIOLET)
    box(ax, 7.7, y, 3.2, 1.2, "Reactive Forwarding\nL2 learning + L3/L4 rules\nidle_timeout 10 s", VIOLET)
    box(ax, 11.7, y, 3.8, 1.2, "Mitigator\nDROP (hard_timeout 60 s)\nOpenFlow meter rate-limit", VIOLET)
    arrow(ax, 2.05, 5.25, 2.05, 8.0, "flow stats +\npktin_rate", tx=0.85)
    arrow(ax, 5.75, 5.25, 5.75, 6.8, style="<|-|>")
    arrow(ax, 13.6, 8.0, 13.6, 5.25, "BLOCK / RATE_LIMIT", tx=1.05)

    # data plane
    box(ax, 6.9, 2.35, 2.2, 0.6, "s1 (core)", AQUA, bold=True)
    box(ax, 3.3, 1.35, 2.4, 0.6, "s2 (client edge)", AQUA, bold=True)
    box(ax, 10.3, 1.35, 2.4, 0.6, "s3 (server edge)", AQUA, bold=True)
    arrow(ax, 7.2, 2.35, 5.2, 1.95, style="-")
    arrow(ax, 8.8, 2.35, 10.8, 1.95, style="-")
    ax.text(4.5, 0.75, "h1 h2 h3 users · h4 attacker", ha="center", fontsize=8.5, color=INK_2)
    ax.text(11.5, 0.75, "h5 web · h6 dns · h7 attacker · h8 user", ha="center", fontsize=8.5, color=INK_2)
    ax.text(8.0, 0.4, "Table 0 = SECURITY (drop / meter → goto 1)     Table 1 = FORWARDING (miss → controller)",
            ha="center", fontsize=8.5, color=INK, style="italic")
    arrow(ax, 9.3, 4.05, 8.6, 2.95, "OpenFlow 1.3 (TCP 6653)\nFlowMod · MeterMod · StatsRequest", style="<|-|>", tx=1.6)

    ax.text(0.2, 9.95, "XAI-SDN-IDS system architecture", fontsize=14, fontweight="bold", va="top")
    fig.savefig(os.path.join(OUT, "architecture.png"))
    plt.close(fig)


def topology():
    fig, ax = canvas(12, 6)
    box(ax, 5.0, 4.6, 2.0, 0.7, "Ryu controller", VIOLET, bold=True)
    box(ax, 5.2, 3.2, 1.6, 0.6, "s1 core", AQUA, bold=True)
    box(ax, 2.2, 2.0, 1.6, 0.6, "s2 edge", AQUA, bold=True)
    box(ax, 8.2, 2.0, 1.6, 0.6, "s3 edge", AQUA, bold=True)
    for x, y in ((6.0, 3.8), (3.0, 2.6), (9.0, 2.6)):
        arrow(ax, 6.0, 4.6, x, y, style="-", ls=":", color=VIOLET)
    arrow(ax, 5.5, 3.2, 3.4, 2.6, "1 Gbps", style="-", ty=0.1)
    arrow(ax, 6.5, 3.2, 8.6, 2.6, "1 Gbps", style="-", ty=0.1)
    hosts_l = [("h1", "10.0.0.1", "user", BLUE), ("h2", "10.0.0.2", "user", BLUE),
               ("h3", "10.0.0.3", "user", BLUE), ("h4", "10.0.0.4", "attacker", ORANGE)]
    hosts_r = [("h5", "10.0.0.5", "web server", AQUA), ("h6", "10.0.0.6", "dns server", AQUA),
               ("h7", "10.0.0.7", "attacker", ORANGE), ("h8", "10.0.0.8", "user", BLUE)]
    for hosts, sx, x0 in ((hosts_l, 3.0, 0.3), (hosts_r, 9.0, 6.3)):
        for i, (n, ipaddr, role, col) in enumerate(hosts):
            x = x0 + i * 1.35
            box(ax, x, 0.35, 1.2, 0.85, f"{n}\n{ipaddr}\n{role}", col, size=7.5)
            arrow(ax, sx, 2.0, x + 0.6, 1.2, style="-", color=INK_2)
    ax.text(0.3, 5.75, "Mininet topology (OpenFlow 1.3, 100 Mbps host links, 1 ms delay)",
            fontsize=12, fontweight="bold", va="top")
    for i, (lbl, col) in enumerate((("user / benign", BLUE), ("server (protected)", AQUA),
                                    ("attacker", ORANGE))):
        ax.add_patch(FancyBboxPatch((8.6, 5.3 - i * 0.32), 0.25, 0.2, boxstyle="round,pad=0,rounding_size=0.04",
                                    facecolor=TINT[col], edgecolor=col))
        ax.text(9.0, 5.4 - i * 0.32, lbl, fontsize=8, va="center", color=INK)
    fig.savefig(os.path.join(OUT, "topology.png"))
    plt.close(fig)


def cgre_flow():
    fig, ax = canvas(13, 8.4)
    cx, w = 3.2, 4.4

    def decision(y, text):
        box(ax, cx - w / 2, y, w, 0.75, text, VIOLET, radius=0.3)

    def outcome(x, y, text, col):
        box(ax, x, y, 3.2, 0.7, text, col, bold=True, size=9)

    box(ax, cx - w / 2, 7.3, w, 0.75, "Window features of source s\n→ RF predicts (class, p)", BLUE)
    steps = [(6.2, "class = benign?", "yes", "NONE · reset history", "gray"),
             (5.1, "G1: p ≥ τ_limit (0.70)?", "no", "NONE · log low confidence", "gray"),
             (4.0, "G4: s is protected asset?", "yes", "ALERT only (never block)", YELLOW),
             (2.9, "G3: top-3 SHAP features ∩\nclass signature ≠ ∅ ?", "no", "ALERT · explanation\ninconsistent", YELLOW),
             (1.8, "G2: flagged in ≥2 of last 3\nwindows?", "no", "ALERT · not persistent", YELLOW)]
    prev, cont = 7.3, None
    for y, text, exit_lbl, out_text, col in steps:
        arrow(ax, cx, prev, cx, y + 0.75, cont, tx=0.3)
        cont = "no" if exit_lbl == "yes" else "yes"
        decision(y, text)
        outcome(7.0, y + 0.02, out_text, col if col != "gray" else INK_2)
        arrow(ax, cx + w / 2, y + 0.37, 7.0, y + 0.37, exit_lbl, ty=0.15)
        prev = y
    arrow(ax, cx, 1.8, cx, 1.35, "yes", tx=0.3)
    decision(0.6, "G1: p ≥ τ_block (0.90)?")
    outcome(7.0, 1.05, "BLOCK · DROP rule\nhard_timeout 60 s", ORANGE)
    outcome(7.0, 0.1, "RATE_LIMIT · OF meter\n1 Mbps, 60 s", YELLOW)
    arrow(ax, cx + w / 2, 1.1, 7.0, 1.4, "yes", ty=0.12)
    arrow(ax, cx + w / 2, 0.8, 7.0, 0.45, "no", ty=-0.1)
    ax.text(10.6, 4.4, "Every outcome is written to\nthe audit log with p, gate\nresults and top-k SHAP\ncontributions.\n\n"
            "Mitigations auto-expire, so the\nsource is re-evaluated: a false\npositive heals itself.",
            fontsize=8.5, color=INK_2, va="center")
    ax.text(0.2, 8.35, "Confidence-Gated Response Engine: decision flow", fontsize=13, fontweight="bold", va="top")
    fig.savefig(os.path.join(OUT, "cgre_flow.png"))
    plt.close(fig)


def ml_pipeline():
    fig, ax = canvas(15, 3.6)
    items = [("Labelled scenarios\n(Mininet: hping3, nmap,\niperf3, curl, ping)", AQUA),
             ("Ryu collect mode\nfeatures_<run>.csv", VIOLET),
             ("Ground truth\nlabels_<run>.csv", AQUA),
             ("build_dataset.py\nlabel + drop edge windows", BLUE),
             ("train.py\n7 models, 5-fold CV +\nheld-out session", BLUE),
             ("rf_model.joblib\n+ SHAP explainer", YELLOW),
             ("Ryu detect mode\n(closed loop)", VIOLET)]
    xs = [0.2, 2.35, 2.35, 4.6, 6.85, 9.1, 11.35]
    ys = [1.4, 2.05, 0.65, 1.4, 1.4, 1.4, 1.4]
    for (t, c), x, y in zip(items, xs, ys):
        box(ax, x, y, 1.95, 1.0 if y == 1.4 else 0.85, t, c, size=7.8)
    arrow(ax, 2.15, 1.95, 2.35, 2.4)
    arrow(ax, 2.15, 1.85, 2.35, 1.1)
    arrow(ax, 4.3, 2.45, 4.6, 2.0)
    arrow(ax, 4.3, 1.05, 4.6, 1.7)
    for x in (6.55, 8.8, 11.05):
        arrow(ax, x, 1.9, x + 0.3, 1.9)
    box(ax, 13.55, 1.4, 1.3, 1.0, "Evaluation\nmetrics +\nablation", ORANGE, size=7.8)
    arrow(ax, 13.3, 1.9, 13.55, 1.9)
    ax.text(0.2, 3.45, "Data & ML pipeline", fontsize=12, fontweight="bold", va="top")
    fig.savefig(os.path.join(OUT, "ml_pipeline.png"))
    plt.close(fig)


if __name__ == "__main__":
    architecture()
    topology()
    cgre_flow()
    ml_pipeline()
    print("diagrams written to", OUT)
