#!/bin/bash
# Start Open vSwitch inside the container before handing over to Mininet.
set -e
modprobe openvswitch 2>/dev/null || echo "[entrypoint] modprobe openvswitch failed (module may already be loaded)"
service openvswitch-switch start
ovs-vsctl --version | head -1
exec "$@"
