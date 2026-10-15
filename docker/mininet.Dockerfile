# Data plane: Mininet + Open vSwitch + traffic/attack generators.
# Must run --privileged with /lib/modules mounted (OVS kernel datapath).
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        mininet openvswitch-switch openvswitch-common kmod \
        iproute2 iputils-ping net-tools ethtool tcpdump \
        hping3 iperf3 nmap curl python3 python3-pip procps \
    && rm -rf /var/lib/apt/lists/*

COPY docker/mininet-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /app
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sleep", "infinity"]
