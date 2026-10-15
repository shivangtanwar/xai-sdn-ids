# XAI-SDN-IDS — Master Project Plan

**Course:** Software Defined Security (CSE 2023, 7th Sem, Cyber Security) — Dr. Sumit Badotra
**Problem Statement #15:** *Explainable AI-Based SDN Intrusion Detection and Automated Flow Response*

> Collect flow statistics from Mininet/OVS, train an ML-based intrusion detector, provide
> feature-level explanations for detected anomalies, and integrate the result with the
> controller so that mitigation rules are installed **only when defined confidence/security
> conditions are satisfied**.

| Evaluation | Date | Phases | Marks |
|---|---|---|---|
| Mid evaluation | **15 Oct 2026** | 1 Problem & Lit Review (10) · 2 Design & Architecture (10) · 3 Implementation (15) | 35 |
| Final evaluation | **16–19 Nov 2026** | 4 Security Mechanism & Innovation (10) · 5 Evaluation & Results (10) · 6 Report (5) · 7 Demo & Viva (10) | 35 |

---

## 1. Problem, Motivation, Objectives

**Problem.** SDN centralises control, which makes the controller an ideal place to detect and
respond to attacks. ML-based IDSs report high accuracy, but in practice they are:
1. **Black boxes.** Operators cannot see *why* a flow was flagged, so they cannot trust an
   automated block or debug it.
2. **Trigger-happy.** Most SDN IDS papers install a DROP rule on the first positive
   prediction. A single false positive then cuts off a legitimate host. Automated response
   without guard-rails is itself an attack surface (an attacker can make the IDS block victims).
3. **Trained offline, evaluated offline.** Many are evaluated on CSV datasets only, and are not
   closed-loop with a live controller.

**Objectives.**
- O1. Build a multi-switch Mininet/OVS testbed with benign and attack traffic: ICMP flood,
  TCP-SYN flood, UDP flood, port scan.
- O2. Build a Ryu application that periodically collects OpenFlow flow statistics and derives
  per-source, time-windowed features.
- O3. Train and compare multi-class ML classifiers on the collected data, and report
  Accuracy, Precision, Recall, F1, FPR and FNR.
- O4. Generate **feature-level explanations** with SHAP for every alert, both locally (per
  alert) and globally (per model).
- O5. Design a **Confidence-Gated Response Engine (CGRE)**. It mitigates only when its
  confidence, persistence, explanation-consistency and asset-safety conditions hold, and it
  applies a graduated response: alert → rate-limit (OpenFlow meter) → DROP with auto-expiry.
- O6. Measure detection latency, mitigation latency, victim throughput/RTT/packet loss,
  controller CPU/memory, and false-mitigation rate with and without gating (ablation).

**Scope.** This is an emulated environment (Mininet + OVS, OpenFlow 1.3, Ryu), with
volumetric and reconnaissance attacks from identifiable sources. *Out of scope:* encrypted
payload inspection, spoofed-source DDoS attribution (listed as future work), and production
deployment.

**Expected outcomes.** A working closed-loop XAI IDS/IPS, a labelled SDN flow dataset, an
evaluation report with graphs, and a live demo where an attack is detected, explained and
mitigated while a high-volume *benign* transfer is **not** blocked.

---

## 2. System Architecture

```
┌─────────────────────────── APPLICATION PLANE ──────────────────────────────┐
│  XAI-IDS Engine                                                            │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐  │
│  │ Feature     │──▶│ ML Detector  │──▶│ SHAP         │──▶│ Confidence-  │  │
│  │ Extractor   │   │ (RF multi-   │   │ Explainer    │   │ Gated Resp.  │  │
│  │ (windowed)  │   │  class)      │   │ (TreeSHAP)   │   │ Engine (CGRE)│  │
│  └─────▲───────┘   └──────────────┘   └──────────────┘   └──────┬───────┘  │
│        │      Audit log (JSON) · REST API · Dashboard            │          │
└────────┼─────────────────────────────────────────────────────────┼──────────┘
         │ flow stats                                   mitigation │ decisions
┌────────┼────────────────── CONTROL PLANE (Ryu, OF1.3) ───────────▼──────────┐
│  Stats Poller (OFPFlowStatsRequest every 2 s) · L3/L4 reactive forwarding   │
│  Mitigator (OFPFlowMod DROP + hard_timeout, OFPMeterMod rate-limit)          │
└────────┬───────────────────────────────────────────────────────────▲─────────┘
         │ OpenFlow 1.3 (TCP 6653)                                   │
┌────────▼──────────────────── DATA PLANE (Mininet + OVS) ───────────┴─────────┐
│                         s1 (core)                                            │
│              ┌────────────┴────────────┐                                     │
│          s2 (client edge)          s3 (server edge)                          │
│     h1 h2 h3 (users) h4 (attacker)  h5 (web) h6 (dns) h7 (attacker) h8 (user) │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Workflow (per polling interval Δt = 2 s)
1. The Ryu app sends `OFPFlowStatsRequest` to every switch, and the replies are cached.
2. The **Feature Extractor** computes per-flow deltas (packets, bytes) since the last poll,
   then aggregates them per **source IP** over the window into 14 interpretable features.
3. The **Detector** predicts a class and its probability for each active source.
4. For non-benign predictions, the **Explainer** computes SHAP values and the top-k features.
5. The **CGRE** evaluates the gate conditions (§4) and decides `NONE | ALERT | RATE_LIMIT | BLOCK`.
6. The **Mitigator** installs the OpenFlow rule on the source's switches. Rules auto-expire
   (`hard_timeout`), after which the source is re-evaluated.
7. Every decision is appended to `results/audit_log.jsonl`, together with its explanation.
   The log is exposed via REST and the dashboard.

### Flow granularity
Reactive rules match `(eth_type, ipv4_src, ipv4_dst, ip_proto, l4_dst_port)` with
`idle_timeout = 10 s`. The source port is excluded on purpose. Otherwise every SYN-flood
packet with a random source port would create a new rule and exhaust the flow table.
Scans still create one rule per probed port, which makes them visible.

---

## 3. Feature Set (per source IP, per window)

| # | Feature | Meaning / attack signal |
|---|---|---|
| 1 | `pkt_rate` | packets/s sent: floods |
| 2 | `byte_rate` | bytes/s sent |
| 3 | `avg_pkt_size` | small packets: SYN/ICMP flood; large: bulk benign |
| 4 | `n_flows` | active flow entries for the source |
| 5 | `new_flows` | flows created this window: scans |
| 6 | `n_dst_ips` | distinct destinations: sweeps |
| 7 | `n_dst_ports` | distinct destination ports: port scan |
| 8 | `frac_tcp` | share of packets that are TCP |
| 9 | `frac_udp` | share of packets that are UDP |
| 10 | `frac_icmp` | share of packets that are ICMP |
| 11 | `pkts_per_flow` | packets per flow: low for scans, high for floods/bulk |
| 12 | `frac_small_flows` | flows with ≤ 2 packets: scan / half-open |
| 13 | `mean_flow_duration` | short-lived vs persistent flows |
| 14 | `pktin_rate` | Packet-In/s caused by the source: control-plane pressure |

Classes: `benign`, `icmp_flood`, `syn_flood`, `udp_flood`, `port_scan`.
Benign traffic deliberately includes **high-volume iperf3 transfers**, so the model cannot
rely on "rate = attack". This is also the main false-positive test for gating.

---

## 4. Innovation — Confidence-Gated Response Engine (CGRE)

A source is mitigated **only if all** of these hold:

| Gate | Condition | Why |
|---|---|---|
| G1 Confidence | `P(attack class) ≥ τ` (τ_block = 0.90, τ_limit = 0.70) | Do not act on uncertain predictions |
| G2 Persistence | flagged in ≥ k of the last n windows (default 2 of 3) | Filter transient spikes |
| G3 Explanation consistency | top-3 SHAP features overlap the class's expected *signature* (e.g. `port_scan` → {`n_dst_ports`, `new_flows`, `frac_small_flows`, `pkts_per_flow`}) | A prediction driven by irrelevant features is suspicious, so it is downgraded to ALERT |
| G4 Asset safety | source is not on the protected list (controller, gateway, critical servers) | Never let the IDS be weaponised against core assets |

**Graduated response:**
- `ALERT` (log + explanation): G1 holds at τ_limit, but G2 or G3 fail.
- `RATE_LIMIT`: an OpenFlow meter (e.g. 1 Mbps) on the source. Used when τ_limit ≤ p < τ_block
  and G2 holds.
- `BLOCK`: a DROP rule at priority 1000 with `hard_timeout = 60 s`. Used when all gates hold
  at τ_block. It auto-expires and the source is re-evaluated, so a false positive heals itself.

Every decision is stored with its probability, gate results and top-k SHAP contributions.
This gives an auditable, human-readable trail for each automated action.

**Ablation:** naive (block on any positive) vs G1 only vs G1+G2 vs full CGRE, compared on
seconds of benign impairment, distinct benign sources hit, attacks mitigated and time to
mitigate (`ml/replay_ablation.py`, plus live runs in Phase 5).

**Phase 4 extension: G5 reflection awareness.** Preliminary data shows that a *victim*
answering a flood (e.g. ICMP echo replies at the attack rate) looks like a flood itself.
G4 protects servers, but any host can be a victim. G5 suppresses mitigation of source S
when S's dominant destination D is itself currently flagged as attacking S, i.e. S's
traffic is a response to an attack.

---

## 5. Technology Choices (justification)

| Component | Choice | Why |
|---|---|---|
| Emulator | Mininet 2.3 + OVS 2.17 | Course standard. Real OVS kernel datapath, OF1.3 meters |
| Controller | **Ryu 4.34** (Python) | Lightweight, Python-native, so it can import scikit-learn/SHAP in-process. Easy flow stats & meters. ODL/ONOS are Java and heavy for ML integration |
| Protocol | OpenFlow 1.3 | Meters (rate-limit), multiple tables, wide OVS support |
| ML | scikit-learn: RandomForest (primary), compared with DT, ExtraTrees, HistGB, LR, MLP | Tree models are fast (< 1 ms inference), accurate on tabular data, and have exact, fast TreeSHAP |
| XAI | SHAP (TreeExplainer) for local + global; LIME as a comparison in the evaluation | Additive and consistent; per-alert explanations in milliseconds |
| Traffic | hping3, nmap, iperf3, ping, curl/HTTP | Controlled, reproducible attack & benign classes |
| Packaging | Docker Compose (controller container + privileged Mininet container) | Reproducible on every teammate's machine. Ryu needs Python 3.9 |
| Validation dataset | InSDN (2020, SDN-specific) for cross-checking | Comparison with published results |

---

## 6. Repository Layout

```
xai-sdn-ids/
├── docker/              controller & mininet images
├── docker-compose.yml
├── topology/topo.py     3-switch, 8-host topology (roles above)
├── controller/
│   └── xai_ids_app.py   Ryu app: forwarding, stats poller, mitigator, REST API
├── ids/
│   ├── features.py      flow-stats → per-source window features
│   ├── detector.py      model loading / prediction
│   ├── explainer.py     SHAP explanations
│   ├── policy.py        Confidence-Gated Response Engine
│   └── config.py        thresholds, signatures, protected assets
├── traffic/scenarios.py labelled benign/attack scenario runner (inside Mininet)
├── ml/
│   ├── build_dataset.py merge feature logs + ground-truth labels
│   ├── train.py         model comparison, metrics, SHAP global plots
│   └── evaluate.py      latency / throughput / ablation experiments
├── data/  models/  results/
├── scripts/             up.sh, collect.sh, demo.sh
└── docs/                plan, literature review, design, report, slides
```

---

## 7. Timeline & Milestones

| When | Milestone | Output |
|---|---|---|
| **15 Oct (today)** | Phase 1–3 | Plan, lit review, architecture, Docker env, topology, Ryu app with stats + features, first dataset & model, slides |
| 16–22 Oct | Data & model | Full labelled dataset (multiple runs, varying rates), model comparison, hyper-parameter tuning, InSDN cross-check |
| 23–29 Oct | Security mechanism | SHAP integration in the loop, CGRE gates, meters, auto-expiry, audit log, REST API |
| 30 Oct–5 Nov | Experiments | Detection metrics, detection/mitigation latency, victim throughput/RTT/loss, CPU/mem, ablation (naive vs gated), LIME vs SHAP |
| 6–12 Nov | Dashboard + report | Live dashboard (alerts + explanations), graphs, final report (IEEE style) |
| 13–15 Nov | Rehearsal | Scripted demo, viva Q&A sheet, backup demo recording |
| **16–19 Nov** | Phase 4–7 | Final evaluation |

## 8. Suggested Team Split (4–5 members)

| Member | Ownership |
|---|---|
| A | Testbed: Docker, topology, traffic/attack scenarios, dataset collection |
| B | Controller: Ryu app, stats poller, mitigator, meters, REST API |
| C | ML: feature engineering, model training/comparison, InSDN cross-check |
| D | XAI + CGRE: SHAP/LIME, gating logic, audit log, dashboard |
| E | Evaluation & documentation: experiments, graphs, literature review, report, slides |

Everyone must be able to explain the whole pipeline in the viva.

## 9. Rubric Mapping

| Rubric item | Where it is satisfied |
|---|---|
| P1 Problem & Lit review | `docs/01_problem_and_literature.md`, `docs/research/` (2020–2026 papers only) |
| P2 Design & Architecture | §2–§5, `docs/02_architecture.md`, diagrams in `docs/diagrams/` |
| P3 Implementation | `controller/`, `ids/`, `topology/`, `traffic/`, `ml/`, Docker |
| P4 Security & Innovation | CGRE (§4): confidence + persistence + explanation-consistency gating, graduated response, auto-expiry, audit trail |
| P5 Evaluation | Accuracy/Precision/Recall/F1/FPR/FNR, confusion matrix, latency, throughput, RTT, loss, CPU/mem, ablation |
| P6 Report | `docs/report/` |
| P7 Demo & Viva | `scripts/demo.sh`, `docs/viva_qa.md` |

## 10. Risks

| Risk | Mitigation |
|---|---|
| Ryu incompatible with modern Python | Pinned Python 3.9 container |
| Host RAM is low (≈2 GB free) | Rate-controlled attacks (`hping3 -i u…`, not `--flood`); small topology; stop other containers during demos |
| Mininet-generated data is "too easy" | Vary rates, include heavy benign traffic, run multiple sessions, cross-check on InSDN |
| Demo failure | Scripted `demo.sh` + recorded backup video |
