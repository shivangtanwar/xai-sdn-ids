# Control plane: OpenDaylight (Karaf + OpenFlow plugin + L2Switch).
#
# ODL 0.24.1's stock distribution boots with NO ODL features installed; the feature
# repositories are referenced from a generated index that this image registers at build
# time, then odl-l2switch-switch and odl-restconf are installed. JRE 21 is the supported
# runtime for this release.
FROM eclipse-temurin:21-jre-jammy

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends curl tar \
    && rm -rf /var/lib/apt/lists/*

ARG ODL_VERSION=0.24.1
RUN curl -sSL --retry 3 -o /tmp/odl.tar.gz \
        "https://nexus.opendaylight.org/content/repositories/opendaylight.release/org/opendaylight/integration/karaf/${ODL_VERSION}/karaf-${ODL_VERSION}.tar.gz" \
    && mkdir -p /opt && tar -xzf /tmp/odl.tar.gz -C /opt \
    && mv /opt/karaf-${ODL_VERSION} /opt/opendaylight \
    && rm /tmp/odl.tar.gz

COPY docker/odl-entrypoint.sh /usr/local/bin/odl-entrypoint.sh
COPY docker/register-odl-features.py /usr/local/bin/register-odl-features.py
RUN chmod +x /usr/local/bin/odl-entrypoint.sh

# Register the bundled ODL feature repositories (the stock index only points at Karaf's
# own features) so `feature:install odl-l2switch-switch` resolves.
RUN python3 /usr/local/bin/register-odl-features.py /opt/opendaylight

EXPOSE 6633 6653 8101 8181 8182
ENTRYPOINT ["/usr/local/bin/odl-entrypoint.sh"]
