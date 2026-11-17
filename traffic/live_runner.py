#!/usr/bin/env python3
"""Always-on testbed for the live dashboard (runs inside the mininet container).

Keeps the topology and background benign traffic running permanently and exposes a small
HTTP API on the internal Docker network (never published to the internet):

    GET  /status   hosts + recent/running episodes
    POST /attack   {"type": "syn_flood", "src": "h4", "dst": "h5", "duration": 30}
    POST /demo     scripted sequence of benign + attack episodes
    POST /stop     stop every running episode (and the demo)

Commands come only from the fixed templates below; request fields are validated against
fixed host/attack lists, so nothing user-supplied reaches a shell.
"""
import json
import os
import random
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mininet.log import info, setLogLevel  # noqa: E402

from topology.topo import HOSTS, build_net  # noqa: E402
from traffic.scenarios import kill_episode, start_background, start_episode, start_services  # noqa: E402

PORT = 9000
# Fixed, moderate intensities (inside the range the model was trained on).
COMMANDS = {
    "syn_flood": "hping3 -S -p 80 -i u1000 {dst}",
    "udp_flood": "hping3 --udp -p 53 -i u1000 -d 128 {dst}",
    "icmp_flood": "hping3 -1 -i u1000 -d 56 {dst}",
    "port_scan": "while true; do nmap -sS -T4 -Pn -n -p 1-3000 {dst} >/dev/null; done",
    "heavy_benign": "iperf3 -c {dst} -t 3600 -b 30M",
}
DEMO = [("heavy_benign", "h1", "h5"), ("syn_flood", "h4", "h5"), ("port_scan", "h7", "h6"),
        ("udp_flood", "h4", "h8"), ("icmp_flood", "h7", "h8")]
DEMO_DURATION, DEMO_GAP = 30, 10


class Runner:
    def __init__(self, net):
        self.net = net
        self.lock = threading.Lock()
        self.episodes = deque(maxlen=200)
        self.procs = {}            # episode id -> Popen
        self.next_id = 1
        self.demo_cancel = threading.Event()
        self.demo_thread = None

    def ip(self, name):
        return HOSTS[name][0]

    def start(self, kind, src, dst, duration, origin="manual"):
        if kind not in COMMANDS:
            raise ValueError(f"unknown traffic type '{kind}'")
        if src not in HOSTS or dst not in HOSTS or src == dst:
            raise ValueError("source and target must be two different hosts h1-h8")
        duration = int(duration)
        if not 5 <= duration <= 120:
            raise ValueError("duration must be between 5 and 120 seconds")
        with self.lock:
            if any(e["src"] == src and e["status"] == "running" for e in self.episodes):
                raise ValueError(f"{src} is already running an episode; stop it first")
            ep = {"id": self.next_id, "type": kind, "src": src, "dst": dst,
                  "src_ip": self.ip(src), "dst_ip": self.ip(dst), "duration": duration,
                  "start": time.time(), "end": None, "status": "running", "origin": origin}
            self.next_id += 1
            cmd = COMMANDS[kind].format(dst=self.ip(dst))
            self.procs[ep["id"]] = start_episode(self.net.get(src), cmd, duration)
            self.episodes.append(ep)
        info(f"*** [{kind}] {src} -> {dst} for {duration}s\n")
        threading.Thread(target=self._reap, args=(ep,), daemon=True).start()
        return ep

    def _reap(self, ep):
        proc = self.procs[ep["id"]]
        proc.wait()
        kill_episode(proc)
        with self.lock:
            if ep["status"] == "running":
                ep["status"] = "done"
            ep["end"] = time.time()
            self.procs.pop(ep["id"], None)

    def stop_all(self):
        self.demo_cancel.set()
        with self.lock:
            running = [(e, self.procs.get(e["id"])) for e in self.episodes if e["status"] == "running"]
            for ep, _proc in running:
                ep["status"] = "stopped"
        for _ep, proc in running:
            if proc is not None:
                kill_episode(proc)
        return len(running)

    def demo(self):
        if self.demo_thread and self.demo_thread.is_alive():
            raise ValueError("a demo is already running")
        self.demo_cancel.clear()

        def run():
            for kind, src, dst in DEMO:
                if self.demo_cancel.is_set():
                    return
                try:
                    self.start(kind, src, dst, DEMO_DURATION, origin="demo")
                except ValueError as e:
                    info(f"*** demo step skipped: {e}\n")
                if self.demo_cancel.wait(DEMO_DURATION + DEMO_GAP):
                    return

        self.demo_thread = threading.Thread(target=run, daemon=True)
        self.demo_thread.start()
        return {"steps": [{"type": k, "src": s, "dst": d} for k, s, d in DEMO],
                "duration": DEMO_DURATION, "gap": DEMO_GAP}

    def status(self):
        with self.lock:
            return {
                "hosts": {n: {"ip": ip, "switch": sw, "role": role} for n, (ip, _m, sw, role) in HOSTS.items()},
                "episodes": list(self.episodes)[-50:],
                "demo_running": bool(self.demo_thread and self.demo_thread.is_alive()),
                "types": list(COMMANDS),
            }


def make_handler(runner):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            length = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(length) or b"{}") if length else {}

        def do_GET(self):
            if self.path == "/status":
                return self._send(runner.status())
            self._send({"error": "not found"}, 404)

        def do_POST(self):
            try:
                if self.path == "/attack":
                    b = self._body()
                    return self._send(runner.start(b.get("type"), b.get("src"), b.get("dst"),
                                                   b.get("duration", 30)))
                if self.path == "/demo":
                    return self._send(runner.demo())
                if self.path == "/stop":
                    return self._send({"stopped": runner.stop_all()})
            except (ValueError, TypeError, json.JSONDecodeError) as e:
                return self._send({"error": str(e)}, 400)
            self._send({"error": "not found"}, 404)

        def log_message(self, fmt, *args):
            pass

    return Handler


def main():
    setLogLevel("info")
    net = build_net()
    net.start()
    try:
        time.sleep(3)
        net.pingAll(timeout=1)
        start_services(net)
        background = start_background(net, random.Random(7))
        runner = Runner(net)
        server = ThreadingHTTPServer(("0.0.0.0", PORT), make_handler(runner))
        info(f"*** live runner listening on :{PORT}\n")
        try:
            server.serve_forever()
        finally:
            runner.stop_all()
            for p in background:
                p.terminate()
    finally:
        net.stop()


if __name__ == "__main__":
    main()
