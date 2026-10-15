# Viva / Evaluation Q&A Prep Sheet

Every team member should be able to answer all of these.

## SDN fundamentals
**Q: What are the three SDN planes in your project?**
Data plane: OVS switches s1–s3 in Mininet, which forward packets and keep per-flow counters.
Control plane: the Ryu controller, which installs rules over OpenFlow 1.3 and polls statistics.
Application plane: the XAI-IDS engine (features → RF → SHAP → CGRE). It runs as a Ryu application.

**Q: Why OpenFlow 1.3 and not 1.0?**
1.3 has meters (needed for rate-limiting), multiple flow tables (our security/forwarding
split) and richer match fields. 1.0 has a single table and no meters.

**Q: How does the controller get statistics?**
Every 2 s it sends an `OFPFlowStatsRequest` (table 1) to each switch. Each `OFPFlowStatsReply`
carries `packet_count`, `byte_count`, `duration_sec` and the match fields of every flow
entry. We subtract the previous round's counters to get per-window deltas.

**Q: What is a table-miss and why does it matter?**
A packet that matches no rule hits the priority-0 table-miss entry and is sent to the
controller as a Packet-In. Floods and scans with new flow keys cause many Packet-Ins,
so `pktin_rate` is one of our features (control-plane pressure).

**Q: Why two tables?**
Table 0 holds security policy (DROP/meter rules; default `goto table 1`). Table 1 holds
forwarding. Mitigation never disturbs forwarding state, and forwarding counters stay clean
for feature extraction. This is policy enforcement separated from forwarding, a core SDS idea.

**Q: Why match on the "service port" rather than the full 5-tuple?**
hping3/SYN floods randomise the source port. A full 5-tuple match would install one rule per
packet and exhaust the flow table, which is itself an attack. Matching the lower port keeps
one rule per service while scans still create one rule per probed port.

## ML & XAI
**Q: Why Random Forest?**
It is accurate on tabular data, needs no scaling, and is fast (well under 1 ms per window).
It also supports exact, fast TreeSHAP. We compared it against DT, ExtraTrees, HistGB, LR,
KNN and MLP (see `results/model_comparison.csv`).

**Q: Why per-source windows instead of per-flow classification?**
Mitigation acts on a source, so classifying the source is the natural unit. Per-source
aggregation also captures fan-out behaviour (a scan is many tiny flows, which no single flow
reveals), and it explains only one window per alert, avoiding the per-flow SHAP cost
reported in [12].

**Q: How did you avoid overfitting / data leakage?**
The test set is a different recording session (different seed, rates, attacker/victim
pairs). Windows straddling episode start/end are dropped as ambiguous. IP addresses are not
features. Heavy benign traffic (iperf3) prevents a "rate = attack" shortcut.

**Q: What is SHAP?**
A game-theoretic attribution method: each feature's Shapley value is its average marginal
contribution to the prediction over all feature coalitions. The values are additive (they sum
to prediction minus base value). TreeExplainer computes them exactly for tree ensembles in
polynomial time.

**Q: Local vs global explanation?**
Local: why this source in this window was classified as `syn_flood`. These go in the audit
log and drive G3. Global: mean |SHAP| across many samples, i.e. which features the model
relies on overall (`results/shap_global_importance.png`).

**Q: Why not LIME?**
LIME fits a random local surrogate, so results vary between runs and are slower. TreeSHAP is
exact and deterministic for our model. We will compare them in Phase 5.

## Security mechanism (CGRE)
**Q: What is new compared to existing work?**
Existing SDN IDSs mitigate on the label or on a single threshold, and their explanations (if
any) are only for humans. Our CGRE (a) uses the SHAP explanation as a gate (G3), (b)
combines confidence, persistence, explanation and asset-safety conditions, and (c) responds
in grades: alert → meter rate-limit → self-expiring DROP. See RG1–RG6 in the literature review.

**Q: Explain G3 with an example.**
For `port_scan` the expected signature is {n_dst_ports, new_flows, n_flows, frac_small_flows,
pkts_per_flow, pktin_rate}. Suppose the model says "port_scan, p=0.95" but the top SHAP
features are mean_flow_duration and frac_icmp. Then the decision isn't based on scan
behaviour, so we only ALERT. This catches out-of-distribution inputs and adversarial
manipulation.

**Q: Why should a block expire?**
A false positive then costs at most 60 s instead of a permanent outage. After expiry the
source is re-evaluated, and if the attack continues it is blocked again within a few seconds.

**Q: Can an attacker abuse your IPS?**
That is exactly what G4 (protected assets never auto-blocked) and G2/G3 address. A remaining
limitation is IP spoofing: with spoofed sources we would block the wrong IP. Future work is
per-ingress-port aggregation and mitigation.

**Q: What are the thresholds and how were they chosen?**
τ_limit 0.70, τ_block 0.90, persistence 2 of 3, rule timeout 60 s. These are initial values.
In Phase 5 we sweep them and plot false mitigations vs. time-to-mitigate.

## Evaluation & limitations
**Q: Which metrics?**
Accuracy, Precision, Recall, F1 (macro), FPR, FNR. Detection latency (attack start → first
flag) and mitigation latency (attack start → rule installed). Victim throughput, RTT and loss.
Controller CPU/memory. Inference and explanation time per alert. Ablation: naive vs. gated.

**Q: Results are very high. Is that realistic?**
Controlled emulated attacks are easier to separate than real traffic, and we say so. We
mitigate this with a held-out session, randomised rates, heavy benign traffic, and a planned
InSDN cross-check plus low-rate attacks in Phase 4–5.

**Q: Limitations?**
Emulated network; attacks from identifiable sources (no spoofing); polling interval bounds
detection latency (≥ 2 s); the model must be retrained for new attack types; Ryu is
single-threaded.

**Q: Future scope?**
Per-port mitigation for spoofed DDoS, online/incremental learning, P4/INT telemetry instead
of polling, multi-controller deployment, LLM-generated natural-language incident summaries
from SHAP output.
