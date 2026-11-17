# Ryu vs OpenDaylight: the same XAI-IDS on two controllers

Your professor asked for ODL to be set up and for attacks to be routed through it so the
two stacks can be compared on time and detection. This is what was built, what it measures,
and what the honest conclusions are.

## What runs

| Arm | Control plane | Southbound | IDS code |
|---|---|---|---|
| Baseline | Ryu 4.34 (`controller/xai_ids_app.py`) | OpenFlow 1.3 event loop | `ids/detector.py`, `ids/explainer.py`, `ids/policy.py` |
| ODL arm | OpenDaylight 0.24.1, OpenFlow plugin 1.0.2 + L2Switch 4.0.2 | RESTCONF polling + `sal-flow` RPCs (`ids/odl_engine.py`) | **the same three modules, unchanged** |

The RF model, the 14 features, SHAP and all four CGRE gates are identical. Only the
southbound plumbing differs — that is the whole point of the comparison.

Files added:

| File | Purpose |
|---|---|
| `ids/odl.py` | RESTCONF client: inventory, per-flow stats, `add-flow`/`remove-flow` RPCs |
| `ids/odl_engine.py` | XAI-IDS driven by ODL; mirrors the Ryu app's REST surface |
| `docker/odl.Dockerfile` + `docker/odl-entrypoint.sh` | ODL 0.24.1 image, features installed at boot |
| `docker/register-odl-features.py` | registers ODL's bundled feature repos (see gotcha #1) |
| `docker-compose.compare.yml` | dual-controller stack (`xai-compare`) |
| `ml/compare_controllers.py` | the benchmark |

## Four things that had to be solved

**1. ODL 0.24.1 boots as bare Karaf.** The stock tarball installs *no* ODL features. Its
`features-index` artifact is a pointer file listing one repository per project; those
repositories are never registered. `docker/register-odl-features.py` adds them at build
time, then `feature:install odl-l2switch-switch odl-restconf` works. Without this step the
controller has no OpenFlow listener at all.

**2. RESTCONF is on 8182, not 8181.** This release serves RFC 8040 through a Netty endpoint
on 8182; 8181 (Pax-Web) answers 404 for every `/restconf` path. Credentials are ODL AAA
`admin/admin`.

**3. L2Switch cannot produce our features.** Its flows match `in-port` only — no IP match
fields, therefore no per-source counters. The IDS needs per-source windows, so the ODL arm
installs its own L3 rules `(src, dst, proto)` via `sal-flow:add-flow` at priority 50 and
reads those counters. Port layout is declared in `HOST_SWITCH` / `HOST_PORT`; Mininet
numbers inter-switch links first, so host links start at port 2 (a bug found and fixed
during bring-up).

**4. ODL's flow counters need care.** Three issues, all visible in the measurements:

- Rules are *declared*, not reactive, so every rule exists before traffic does. Unmatched
  rules report `packets=0`; they must be filtered out or `n_flows`/`n_dst_ips` explode.
- Traffic crosses 2–3 switches, so one packet is counted 2–3 times. Filtering to the
  source's ingress switch (known statically) gives the same semantics as the Ryu app.
- `duration` comes from the datastore entry, not the flow's idle lifetime. A statically
  provisioned rule ages with the mesh. Since `mean_flow_duration` is a discriminating
  feature, this is the **main accuracy gap** between the two arms.

## Results measured live

**Forwarding mesh provisioning.** 504 rules (8 sources × 7 destinations × 3 protocols ×
3 switches) took **4 m 13 s** — about **500 ms per `sal-flow:add-flow` RPC**. The Ryu app
installs the same forwarding state reactively from Packet-Ins at packet arrival, with no
per-rule HTTP round trip. On a 3-switch fabric this is the single largest difference and it
is architectural: RESTCONF is request/response, the Ryu event loop is not.

**Polling.** One IDS window costs **~35 ms** on ODL (3 RESTCONF GETs, one per switch, each
returning the full flow table) versus **~1 ms** in Ryu (the controller already holds the
stats; the REST call just reads a computed round). Both run on the same 2 s tick, so the
budget fits, but ODL spends 3.5% of the window on measurement and Ryu spends 0.05%.

**Detection.** SYN flood (h4 → h5, 740 pkt/s): detected as `syn_flood` through ODL at
p = 0.71–0.73, against p > 0.97 through Ryu. The gap traces to `mean_flow_duration`
(1329 s on ODL because the rule aged with the mesh, 18–147 s in the Ryu training data).
Confidence is above τ_limit (0.70) but below τ_block (0.90), so the same CGRE reaches
**RATE_LIMIT** instead of **BLOCK**. The gating logic is behaving correctly — it is the
input feature that differs.

## The honest conclusion

ODL is the right answer for a *production* SDN control plane and the comparison is worth
showing, but for this IDS it is a **slower path to the same decisions**, and slightly less
accurate, for a specific and explainable reason: the IDS needs per-source flow counters
that only exist because we install the rules ourselves, and rules that exist before their
traffic lose the duration signal the model leans on.

That is a defensible finding to present. It maps directly onto the architecture argument in
the report: the CGRE is controller-agnostic (proved by running it unchanged on both), while
the *quality* of the features depends on how tightly the controller couples statistics to
traffic — which is exactly what an event-driven controller does better.

If asked "would you use ODL?", the answer is: yes for policy and multi-vendor southbound,
no for a latency-sensitive detection loop on this hardware. A hybrid (ODL for control,
Ryu-style stats for the IDS) is the natural next step.

## Reproducing

```bash
docker compose -f docker-compose.compare.yml up -d --build
# provision the L3 mesh once (~4 min), then run the IDS
docker exec cmp-odl-ids python -m ids.odl_engine --odl http://odl:8182 --provision
docker exec -d cmp-odl-ids python -m ids.odl_engine --odl http://odl:8182 --api-port 8080
python3 ml/compare_controllers.py --ryu http://127.0.0.1:8088 --odl http://127.0.0.1:8182
```
