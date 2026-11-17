#!/bin/bash
# Boot OpenDaylight, wait for Karaf, install the OpenFlow + L2Switch features, then run
# the server in the foreground.
set -e
ODL_HOME=/opt/opendaylight
export JAVA_HOME="${JAVA_HOME:-/opt/java/openjdk}"

echo "[odl] starting Karaf"
"$ODL_HOME/bin/karaf" server > /var/log/odl-boot.log 2>&1 &
KARAF_PID=$!
echo "$KARAF_PID" > /tmp/karaf.pid

echo "[odl] waiting for the Karaf shell on 8101"
for _ in $(seq 90); do
    if (echo > /dev/tcp/127.0.0.1/8101) 2>/dev/null; then break; fi
    sleep 2
done

echo "[odl] installing odl-l2switch-switch and odl-restconf"
printf 'feature:install odl-l2switch-switch odl-restconf\nlogout\n' \
    | "$ODL_HOME/bin/client" -a 8101 -u karaf -p karaf -b || true

echo "[odl] waiting for OpenFlow (6653) and RESTCONF (8182)"
for _ in $(seq 120); do
    of=0; rc=0
    (echo > /dev/tcp/127.0.0.1/6653) 2>/dev/null && of=1
    (echo > /dev/tcp/127.0.0.1/8182) 2>/dev/null && rc=1
    [ "$of" = 1 ] && [ "$rc" = 1 ] && break
    sleep 2
done
echo "[odl] ready"

# Keep the container alive on the Karaf process, not the shell.
wait "$KARAF_PID"
