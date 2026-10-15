# XAI-SDN-IDS

**Explainable AI-Based SDN Intrusion Detection and Automated Flow Response**
(Software Defined Security, Problem Statement #15)

Ryu (OpenFlow 1.3) polls flow statistics from a Mininet/OVS network. A Random Forest
classifies per-source traffic windows, SHAP explains every alert, and a **Confidence-Gated
Response Engine** only installs mitigation rules (meter rate-limit or self-expiring DROP)
when confidence, persistence, explanation-consistency and asset-safety conditions hold.

- Plan & architecture: [`docs/00_PROJECT_PLAN.md`](docs/00_PROJECT_PLAN.md)
- Phase 1–3 report: [`docs/report/phase1-3_report.md`](docs/report/phase1-3_report.md)
- Literature review (2020–2026, verified): [`docs/research/literature_review.md`](docs/research/literature_review.md)

## Quick start

Requirements: Linux with Docker (the host kernel needs the `openvswitch` module, which the
privileged Mininet container loads).

```bash
docker compose build                       # controller (Py3.9 + Ryu + SHAP) and mininet images

# 1. collect a labelled dataset (controller in collect mode + scenario runner)
scripts/collect.sh train1 11 20 30         # run name, seed, episodes, seconds/episode
scripts/collect.sh test1 22 15 30

# 2. label + train + figures (models/rf_model.joblib, results/*.png|csv)
docker run --rm -v "$PWD":/app -w /app xai-sdn-ids/controller python ml/build_dataset.py train1 test1
docker run --rm -v "$PWD":/app -w /app xai-sdn-ids/controller python ml/train.py --train train1 --test test1

# 3. closed-loop demo (detect -> explain -> gate -> mitigate)
scripts/demo.sh                            # or: scripts/demo.sh monitor  (never mitigates)
curl -s localhost:8088/xai/alerts          # REST: recent decisions with SHAP explanations
curl -s localhost:8088/xai/mitigations
curl -s -X DELETE localhost:8088/xai/mitigations/10.0.0.4   # operator override

# interactive Mininet CLI against the running controller
docker compose run --rm --no-deps mininet python3 topology/topo.py

# unit tests
docker run --rm -v "$PWD":/app -w /app xai-sdn-ids/controller python -m unittest -v
```

## Layout

| Path | Purpose |
|---|---|
| `controller/xai_ids_app.py` | Ryu app: two-table pipeline (security / forwarding), stats poller, mitigator, REST |
| `ids/` | features, detector, SHAP explainer, response engine (`policy.py`), config |
| `topology/topo.py` | 3 switches, 8 hosts (users, servers, attackers) |
| `traffic/scenarios.py` | labelled benign + attack episodes (hping3, nmap, iperf3, curl, ping) |
| `ml/` | dataset building, training & model comparison, audit summary, plot style |
| `docs/` | plan, report, literature review, diagrams |
