#!/usr/bin/env python3
"""Point OpenDaylight's Karaf at the ODL feature repositories that ship inside the
distribution but are not registered in the stock config.

`etc/org.apache.karaf.features.cfg` in the 0.24.x tarball lists only a single generated
feature (the Karaf framework itself) plus the local `features-index` artifact. That index
is a *pointer file*: it references one features XML per project (aaa, mdsal, openflowplugin,
l2switch, ...). Registering those repositories is what makes `feature:install
odl-l2switch-switch` possible; without it the controller boots as bare Karaf with no
OpenFlow support at all.

    python3 register-odl-features.py /opt/opendaylight
"""
import glob
import os
import re
import sys

# Only the projects needed for an OpenFlow switch; fewer repositories = faster resolution.
WANTED = ("aaa", "controller", "infrautils", "l2switch", "mdsal", "odlparent",
          "openflowplugin", "yangtools")


def main(home):
    index = glob.glob(os.path.join(home, "system", "org", "opendaylight", "integration",
                                   "features-index", "*", "*features.xml"))
    if not index:
        sys.exit("features-index artifact not found; is this an ODL distribution?")
    text = open(index[0]).read()
    repos = re.findall(r"<repository>([^<]+)", text)
    selected = [r for r in repos if any(f"/{w}/" in r for w in WANTED)]
    if not selected:
        sys.exit("no matching feature repositories in the index")

    cfg_path = os.path.join(home, "etc", "org.apache.karaf.features.cfg")
    cfg = open(cfg_path).read()
    current = re.search(r"(?m)^featuresRepositories\s*=\s*(.*)$", cfg).group(1).strip()
    merged = ",".join([current] + [r for r in selected if r not in current])
    cfg = re.sub(r"(?m)^featuresRepositories\s*=.*$", "featuresRepositories = " + merged, cfg, count=1)
    open(cfg_path, "w").write(cfg)
    print(f"registered {len(selected)} ODL feature repositories")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/opt/opendaylight")
