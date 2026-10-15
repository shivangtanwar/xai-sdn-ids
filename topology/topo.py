#!/usr/bin/env python3
"""XAI-SDN-IDS testbed: 3 OVS switches (core + 2 edges), 8 hosts, remote Ryu controller.

                    s1 (core)
              ┌─────────┴─────────┐
        s2 (client edge)     s3 (server edge)
   h1 h2 h3 users, h4 attacker   h5 web, h6 dns, h7 attacker, h8 user

Usage (inside the mininet container):
    python3 topology/topo.py                # interactive CLI
    python3 topology/topo.py --no-cli ...   # used by traffic/scenarios.py
"""
import argparse
import socket

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

HOSTS = {
    # name: (ip, mac, switch, role)
    "h1": ("10.0.0.1", "00:00:00:00:00:01", "s2", "user"),
    "h2": ("10.0.0.2", "00:00:00:00:00:02", "s2", "user"),
    "h3": ("10.0.0.3", "00:00:00:00:00:03", "s2", "user"),
    "h4": ("10.0.0.4", "00:00:00:00:00:04", "s2", "attacker"),
    "h5": ("10.0.0.5", "00:00:00:00:00:05", "s3", "web-server"),
    "h6": ("10.0.0.6", "00:00:00:00:00:06", "s3", "dns-server"),
    "h7": ("10.0.0.7", "00:00:00:00:00:07", "s3", "attacker"),
    "h8": ("10.0.0.8", "00:00:00:00:00:08", "s3", "user"),
}


class XaiIdsTopo(Topo):
    def build(self, bw=100, delay="1ms"):
        s1 = self.addSwitch("s1", dpid="0000000000000001", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", dpid="0000000000000002", protocols="OpenFlow13")
        s3 = self.addSwitch("s3", dpid="0000000000000003", protocols="OpenFlow13")
        self.addLink(s1, s2, bw=bw * 10, delay=delay)
        self.addLink(s1, s3, bw=bw * 10, delay=delay)
        for name, (ip, mac, sw, _role) in HOSTS.items():
            h = self.addHost(name, ip=ip + "/24", mac=mac)
            self.addLink(h, sw, bw=bw, delay=delay)


def build_net(controller_host="controller", controller_port=6653, bw=100):
    ctrl_ip = socket.gethostbyname(controller_host)
    net = Mininet(
        topo=XaiIdsTopo(bw=bw),
        switch=OVSSwitch,
        controller=None,
        link=TCLink,
        autoSetMacs=False,
        build=False,
    )
    net.addController("c0", controller=RemoteController, ip=ctrl_ip, port=controller_port)
    net.build()
    return net


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--controller", default="controller")
    parser.add_argument("--port", type=int, default=6653)
    parser.add_argument("--bw", type=int, default=100, help="host link bandwidth (Mbps)")
    args = parser.parse_args()

    setLogLevel("info")
    net = build_net(args.controller, args.port, args.bw)
    net.start()
    info("*** Roles:\n")
    for name, (ip, _mac, sw, role) in HOSTS.items():
        info(f"    {name} {ip:<10} on {sw}  {role}\n")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
