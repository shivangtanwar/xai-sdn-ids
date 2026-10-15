#!/usr/bin/env python3
"""Labelled traffic generator for the XAI-SDN-IDS testbed (runs inside the mininet container).

Background benign traffic runs for the whole session. Attacks (and heavy-but-benign
"flash crowd" episodes) are injected one at a time, and every episode's ground truth is
written as (src_ip, label, start, end) to data/raw/labels_<run>.csv.

    python3 traffic/scenarios.py --run r1 --episodes 16 --seed 1
    python3 traffic/scenarios.py --demo      # short scripted demo sequence
"""
import argparse
import csv
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mininet.log import setLogLevel, info  # noqa: E402

from topology.topo import HOSTS, build_net  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATTACKERS = ["h4", "h7"]
VICTIMS = ["h5", "h6", "h8"]
USERS = ["h1", "h2", "h3", "h8"]


def ip(name):
    return HOSTS[name][0]


# ------------------------------------------------------------------ episode generators
# Each returns a shell command run on the source host; rates are randomised so the model
# cannot memorise one exact packet rate.
def icmp_flood(dst, rng):
    gap = rng.choice([400, 700, 1000, 2000, 4000])
    return f"hping3 -1 -i u{gap} -d {rng.choice([0, 56, 120, 500])} {dst}"


def syn_flood(dst, rng):
    gap = rng.choice([400, 700, 1000, 2000, 4000])
    return f"hping3 -S -p {rng.choice([80, 80, 22, 443])} -i u{gap} {dst}"


def udp_flood(dst, rng):
    gap = rng.choice([400, 700, 1000, 2000, 4000])
    return f"hping3 --udp -p {rng.choice([53, 53, 123, 5060])} -i u{gap} -d {rng.choice([0, 64, 256, 512])} {dst}"


def port_scan(dst, rng):
    timing = rng.choice(["-T3", "-T4", "-T4 --max-rate 300", "-T5"])
    kind = rng.choice(["-sS", "-sS", "-sT"])
    return f"while true; do nmap {kind} {timing} -Pn -n -p 1-3000 {dst} >/dev/null; done"


def heavy_benign(dst, rng):
    """High-volume legitimate transfer (the classic false-positive trap)."""
    if rng.random() < 0.5:
        return f"iperf3 -c {dst} -t 300 -b {rng.choice(['20M', '50M', '0'])}"
    return f"iperf3 -c {dst} -u -t 300 -b {rng.choice(['5M', '10M'])} -l 1200"


ATTACKS = {"icmp_flood": icmp_flood, "syn_flood": syn_flood,
           "udp_flood": udp_flood, "port_scan": port_scan}


# ------------------------------------------------------------------ helpers
def start_services(net):
    h5, h6, h8 = net.get("h5", "h6", "h8")
    for h in (h5, h6, h8):
        h.cmd("iperf3 -s -D")
    h5.cmd("cd /tmp && python3 -m http.server 80 >/dev/null 2>&1 &")
    h6.cmd("python3 -m http.server 8053 >/dev/null 2>&1 &")


def start_background(net, rng):
    """Normal user activity: web browsing, pings, low-rate streams, DNS-like queries."""
    procs = []
    for name in USERS:
        h = net.get(name)
        target = ip(rng.choice(["h5", "h6"]))
        procs.append(h.popen(
            f"while true; do curl -s -o /dev/null http://{ip('h5')}/; sleep 0.$((RANDOM%9+1)); done",
            shell=True))
        procs.append(h.popen(f"ping -i 0.{rng.randint(3, 9)} {target}", shell=True))
    procs.append(net.get("h3").popen(f"iperf3 -c {ip('h6')} -u -b 1M -t 100000 -l 800", shell=True))
    procs.append(net.get("h2").popen(f"hping3 --udp -p 53 -i u100000 -d 40 {ip('h6')}", shell=True))
    return procs


def stop(procs):
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass


def run_episode(net, writer, label, src, dst, cmd, duration):
    info(f"*** [{label}] {src} -> {dst} for {duration}s: {cmd}\n")
    h = net.get(src)
    # `timeout` signals its whole process group, so looping commands (while true; nmap)
    # cannot outlive the episode and pollute the next "benign" windows.
    quoted = cmd.replace("'", "'\\''")
    start = time.time()
    proc = h.popen(f"timeout -s KILL {duration} bash -c '{quoted}'", shell=True)
    proc.wait()
    end = time.time()
    h.cmd("pkill -9 -f hping3; pkill -9 -f nmap; pkill -9 -f 'iperf3 -c'")
    writer.writerow([ip(src), label, f"{start:.3f}", f"{end:.3f}"])


def plan_episodes(n, rng):
    """Balanced shuffled list of (label, src, dst)."""
    labels = (list(ATTACKS) + ["heavy_benign"]) * (n // 5 + 1)
    rng.shuffle(labels)
    plan = []
    for label in labels[:n]:
        if label == "heavy_benign":
            src = rng.choice(USERS)
            dst = rng.choice([v for v in ["h5", "h6", "h8"] if v != src])
        else:
            src = rng.choice(ATTACKERS + (["h3"] if rng.random() < 0.2 else []))
            dst = rng.choice(VICTIMS)
        plan.append((label, src, dst))
    return plan


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", default=time.strftime("run_%Y%m%d_%H%M%S"))
    parser.add_argument("--episodes", type=int, default=15)
    parser.add_argument("--duration", type=int, default=30, help="seconds per episode")
    parser.add_argument("--gap", type=int, default=12, help="benign-only seconds between episodes")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--demo", action="store_true", help="short scripted demo sequence")
    args = parser.parse_args()

    setLogLevel("info")
    rng = random.Random(args.seed)
    net = build_net()
    net.start()
    os.makedirs(os.path.join(ROOT, "data", "raw"), exist_ok=True)
    label_path = os.path.join(ROOT, "data", "raw", f"labels_{args.run}.csv")
    background = []
    try:
        info("*** waiting for switches + warming up ARP\n")
        time.sleep(3)
        net.pingAll(timeout=1)
        start_services(net)
        background = start_background(net, rng)
        time.sleep(args.gap)

        if args.demo:
            plan = [("heavy_benign", "h1", "h5"), ("syn_flood", "h4", "h5"),
                    ("port_scan", "h7", "h6"), ("udp_flood", "h4", "h8")]
        else:
            plan = plan_episodes(args.episodes, rng)

        with open(label_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["src_ip", "label", "start", "end"])
            for i, (label, src, dst) in enumerate(plan, 1):
                info(f"*** episode {i}/{len(plan)}\n")
                gen = heavy_benign if label == "heavy_benign" else ATTACKS[label]
                run_episode(net, writer, label, src, ip(dst), gen(ip(dst), rng), args.duration)
                f.flush()
                time.sleep(args.gap)
        info(f"*** ground truth written to {label_path}\n")
    finally:
        stop(background)
        net.stop()


if __name__ == "__main__":
    main()
