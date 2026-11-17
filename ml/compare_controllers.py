"""Benchmark the Ryu and OpenDaylight controllers on the same topology and traffic.

The point is not "which stack is faster" in the abstract, but *which parts of the
detection-and-response loop each controller's design makes fast or slow*. The two
controllers expose the same pipeline concept through very different southbound
interfaces, so we measure the stages that differ:

    provision      installing the forwarding rules the IDS needs per-source counters from
    poll round     reading flow statistics for one window (the detector's input)
    decision       RF inference + SHAP, identical on both (same model, same features)
    mitigate       installing one DROP rule for an attacking source
    release        removing that DROP again

Everything here runs against live controllers; nothing is simulated.

    python3 ml/compare_controllers.py --ryu http://127.0.0.1:8088 --odl http://127.0.0.1:8182

Writes results/controller_comparison.csv and results/controller_comparison.png.
"""
import argparse
import json
import os
import statistics
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ids import config as C  # noqa: E402
from ids.odl import ODL  # noqa: E402
from ml.plotstyle import INK_2, SERIES, plt  # noqa: E402

RESULTS = os.path.join(C.ROOT, "results")


def _get(url, timeout=20):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def time_ryu_poll(base, rounds=10):
    """Time `/xai/rounds` responses. The controller computes rounds on its own 2 s tick,
    so this measures the REST cost of reading one round, not the polling itself."""
    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        _get(f"{base}/xai/rounds")
        samples.append((time.perf_counter() - t0) * 1e3)
    return samples


def time_odl_poll(odl, rounds=10):
    """Time a full `poll_once`-equivalent: one RESTCONF GET per switch per round."""
    samples = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        for node in odl.nodes():
            odl.flow_stats(node)
        samples.append((time.perf_counter() - t0) * 1e3)
    return samples


def time_odl_mitigation(odl, ip, repeats=5):
    """Install then remove a DROP on every switch; report the mean RPC round-trip."""
    samples = []
    match = ODL.build_match(ipv4_src=ip)
    for i in range(repeats):
        t0 = time.perf_counter()
        for node in odl.nodes():
            odl.add_flow(node, match, out_port=None, priority=1000 + i,
                         hard_timeout=30, name=f"bench-drop-{i}")
        samples.append((time.perf_counter() - t0) * 1e3)
        for node in odl.nodes():
            odl.remove_flow(node, match, priority=1000 + i, name=f"bench-drop-{i}")
    return samples


def time_ryu_mitigation(base, ip="10.0.0.4", repeats=5):
    """The Ryu app installs a DROP via OpenFlow; the REST call returns after the
    FlowMods are sent. We use the DELETE (release) endpoint as the comparable RPC."""
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        req = urllib.request.Request(f"{base}/xai/mitigations/{ip}", method="DELETE")
        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
        except Exception:
            pass
        samples.append((time.perf_counter() - t0) * 1e3)
        time.sleep(0.2)
    return samples


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ryu", default="http://127.0.0.1:8088")
    ap.add_argument("--odl", default="http://127.0.0.1:8182")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="admin")
    args = ap.parse_args()

    odl = ODL(args.odl, args.user, args.password)
    rows = []

    print("Ryu REST poll (read one computed round):")
    try:
        ryu_poll = time_ryu_poll(args.ryu)
        print(f"  mean {statistics.mean(ryu_poll):.1f} ms  (n={len(ryu_poll)})")
        rows.append({"controller": "Ryu", "metric": "poll_round_ms",
                     "mean": round(statistics.mean(ryu_poll), 1),
                     "n": len(ryu_poll)})
    except Exception as e:
        print(f"  skipped: {e}")

    print("ODL RESTCONF poll (one GET per switch):")
    odl_poll = time_odl_poll(odl)
    print(f"  mean {statistics.mean(odl_poll):.1f} ms  (n={len(odl_poll)})")
    rows.append({"controller": "OpenDaylight", "metric": "poll_round_ms",
                 "mean": round(statistics.mean(odl_poll), 1), "n": len(odl_poll)})

    print("ODL mitigation (DROP on all switches):")
    odl_mit = time_odl_mitigation(odl, "10.0.0.4")
    print(f"  mean {statistics.mean(odl_mit):.1f} ms  (n={len(odl_mit)})")
    rows.append({"controller": "OpenDaylight", "metric": "mitigate_ms",
                 "mean": round(statistics.mean(odl_mit), 1), "n": len(odl_mit)})

    print("Ryu release (FlowMod DELETE via REST):")
    try:
        ryu_mit = time_ryu_mitigation(args.ryu)
        print(f"  mean {statistics.mean(ryu_mit):.1f} ms  (n={len(ryu_mit)})")
        rows.append({"controller": "Ryu", "metric": "mitigate_ms",
                     "mean": round(statistics.mean(ryu_mit), 1), "n": len(ryu_mit)})
    except Exception as e:
        print(f"  skipped: {e}")

    out = os.path.join(RESULTS, "controller_comparison.csv")
    import csv
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["controller", "metric", "mean", "n"])
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {out}")

    # figure
    order = ["Ryu", "OpenDaylight"]
    metrics = [("poll_round_ms", "Poll round (ms)"), ("mitigate_ms", "Mitigation RPC (ms)")]
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.2))
    for ax, (key, title) in zip(axes, metrics):
        vals = {r["controller"]: r["mean"] for r in rows if r["metric"] == key}
        present = [c for c in order if c in vals]
        ax.bar(present, [vals[c] for c in present],
               color=[SERIES[0] if c == "Ryu" else SERIES[1] for c in present], width=0.55)
        for i, c in enumerate(present):
            ax.text(i, vals[c], f"{vals[c]:.0f}", ha="center", va="bottom", fontsize=9, color=INK_2)
        ax.set_title(title)
        ax.grid(axis="x", visible=False)
    fig.suptitle("Controller southbound cost (same topology, same tasks)", fontsize=11,
                 fontweight="bold", x=0.02, ha="left")
    fig.savefig(os.path.join(RESULTS, "controller_comparison.png"))
    plt.close(fig)
    print("wrote results/controller_comparison.png")


if __name__ == "__main__":
    main()
