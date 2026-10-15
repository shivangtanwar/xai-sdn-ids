# Literature Review: Explainable AI-Based SDN Intrusion Detection and Automated Flow Response

**Course:** Software Defined Security (BTech final-year project)
**Scope rule:** Only research papers published 2020–2026. Every entry below was checked online (Crossref metadata and/or arXiv, plus the publisher, indexing, or repository page). See "Verification notes" at the end.
**Compiled:** October 2026

> Note on peer review: two entries ([12], [13]) are arXiv **preprints** and are not yet peer-reviewed. We include them because [12] is the closest prior work to our design, and leaving it out would make our gap analysis dishonest. [13] directly informs our "explanation-consistency" check. Please cite them as preprints.

---

## 1. Summary Table

Legend: **XAI?** means feature-level explanations (SHAP/LIME/etc.) are produced. **Automated mitigation?** means the system itself installs or enforces a response. **Confidence gating?** means mitigation is conditional on explicit confidence or other safety conditions rather than on a raw label.

| # | Authors | Year | Title | Venue | Approach | Dataset | XAI? | Automated mitigation? | Confidence gating? | Key limitation |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Elsayed et al. | 2020 | InSDN: A Novel SDN Intrusion Dataset | IEEE Access | Builds an SDN-specific intrusion dataset on an ONOS + Mininet/OVS testbed (attacker VM, Metasploitable, DVWA). Benchmarks 8 ML classifiers on CICFlowMeter features | InSDN (≈344k flows; DoS, DDoS, probe, brute-force, web, botnet, exploitation + normal) | No | No | No | Dataset only, with no response loop. Features are CICFlowMeter packet-level flow features, not the OpenFlow counters a controller can poll. Classes are imbalanced |
| 2 | Novaes et al. | 2020 | Long Short-Term Memory and Fuzzy Logic for Anomaly Detection and Mitigation in Software-Defined Network Environment | IEEE Access | LSTM predicts normal traffic. A dynamic Bienaymé–Chebyshev threshold plus fuzzy logic flags anomalies, followed by a mitigation phase (DDoS and port scan) | Floodlight + Mininet IP flows; CIC-DDoS2019 | No | Yes (Floodlight) | Partial: dynamic statistical threshold and fuzzy rules, but no classifier-probability, persistence, explanation or whitelist checks | Mitigation decisions are not explained to operators. Anomaly-based, so it does not report the attack class in the detail a multi-class classifier would |
| 3 | Tan et al. | 2020 | A New Framework for DDoS Attack Detection and Defense in SDN Environment | IEEE Access | Data-plane trigger screens abnormal flows, then K-Means + KNN on rate/asymmetry features at the controller, which then takes defensive actions | Own SDN experiments | No | Yes | Partial: two-stage (trigger, then ML) check before action | DDoS-only. No explanations. No configurable confidence or persistence policy and no rule auto-expiry is described in the abstract |
| 4 | Chouhan et al. | 2023 (online 2022) | A framework to detect DDoS attack in Ryu controller based software defined networks using feature extraction and classification | Applied Intelligence | Extracts features from live Ryu/SDN traffic. Compares SVM, RF, KNN, XGBoost and NB, and deploys SVM in the controller | Own live SDN traffic | No | No (detection deployed in controller) | No | Detection-focused. No mitigation policy and no explanations. Binary DDoS vs. normal |
| 5 | Alashhab et al. | 2024 | Enhancing DDoS Attack Detection and Mitigation in SDN Using an Ensemble Online Machine Learning Model | IEEE Access | Ensemble online learning with dynamic feature selection, built in Mininet + Ryu, covering detection and mitigation | Custom Mininet/Ryu data; CIC-DDoS2019; InSDN; slow-read DDoS | No | Yes (Ryu) | Not reported in abstract | No feature-level explanation of why a flow was mitigated. False-positive handling is not a stated design goal |
| 6 | El Kamel et al. | 2022 | On-the-fly (D)DoS attack mitigation in SDN using Deep Neural Network-based rate limiting | Computer Communications | Controller-side sliding-window rate limiting. A parallel online DL algorithm updates per-node weights. Trust scores penalise misbehaving hosts/switches by temporarily blocking new flows/PacketIn | Simulated SDN | No | Yes (rate limiting + temporary blocking) | Partial: per-host trust scores, so responses are graded rather than uniform | Rate limiting depends on learned weights that are not explained. The paper argues that uniform rate limiting penalises benign hosts, which motivates per-source, graduated responses |
| 7 | Wang et al. | 2020 | An Explainable Machine Learning Framework for Intrusion Detection Systems | IEEE Access | SHAP local + global explanations of IDS. Compares one-vs-all and multi-class classifiers | NSL-KDD | Yes (SHAP) | No | No | Legacy, non-SDN dataset. Offline only. Explanations are for analysts and do not drive any response |
| 8 | Neupane et al. | 2022 | Explainable Intrusion Detection Systems (X-IDS): A Survey of Current Methods, Challenges, and Opportunities | IEEE Access | Survey of black-box and white-box X-IDS. Proposes a generic human-in-the-loop X-IDS architecture | Survey | Survey of XAI | No | Discusses human-in-the-loop, not automated gating | Not SDN-specific. Calls for explanation-evaluation metrics and stakeholder-specific explanations, which are still open |
| 9 | Gaspar et al. | 2024 | Explainable AI for Intrusion Detection Systems: LIME and SHAP Applicability on Multi-Layer Perceptron | IEEE Access | Applies LIME and SHAP to an MLP IDS. Validates explanations by perturbation (removing top-ranked features) and with a user survey | ADFA-LD (system calls; IoT host IDS) | Yes (LIME, SHAP) | No | No | Host-based (system calls), not network flows. Explanation validation is offline and not used at decision time |
| 10 | Raihan & Islam | 2024 | Enhancing Transparency in DDoS Detection on SDN Using Explainable ML Models | ICICT 2024 (IEEE) | Tuned XGBoost for DDoS detection in an SDN context with post-hoc XAI | CIC-DDoS2019 | Yes (post-hoc XAI) | No | No | Offline dataset study. No controller integration or response. Short conference paper (5 pp.) |
| 11 | Saykat et al. | 2026 | An efficient and interpretable intrusion detection framework for software-defined networks with multi-class imbalanced data using genetic and GAN-based optimization | Scientific Reports | WGAN-GP class balancing, ANOVA + GA feature selection, grid-tuned XGBoost ("OptiXGB-IDS"), with SHAP, LIME, Morris sensitivity and permutation analysis | InSDN; CIC-IDS2017 | Yes (SHAP, LIME, others) | No | No | Authors state there is no live-network testing and evaluation on historical data only. No controller integration or mitigation |
| 12 | Ahmad et al. (preprint) | 2026 | XAI-SDN: An Explainable Entropy-Guided Machine Learning Framework for Real-Time DDoS Detection in Software Defined Networks | arXiv:2609.05701 | CICFlowMeter features + 8 rolling Shannon-entropy metrics, Random Forest + SHAP TreeExplainer. Ryu/OpenFlow architecture with drop-rule feedback described | CIC-DDoS2019 (SYN partition, 3.59M flows) | Yes (SHAP TreeExplainer) | Described (alerts + flow-mod drop rules) but evaluated offline | Single detection threshold (τ = 0.70) only | Binary (benign vs. DDoS), SYN only, offline. SHAP is appended to alerts for SOC triage and is not used in the mitigation decision. Per-flow SHAP cuts throughput from about 60.6k to about 1.95k flows/s. Not peer-reviewed |
| 13 | Alquliti et al. (preprint) | 2025 | Evaluating Explanation Quality in X-IDS Using Feature Alignment Metrics | arXiv:2505.08006 | Metrics measuring how well X-IDS explanations align with domain-knowledge feature sets per attack type | X-IDS benchmark evaluation (see paper) | Evaluates XAI | No | No | Offline evaluation tool. Alignment is not used as a runtime condition for response. Not peer-reviewed |
| 14 | Mohsin et al. | 2026 | A Unified Framework for Human–AI Collaboration in Security Operations Centers with Trusted Autonomy | ACM Trans. Internet Technology | Five-level AI-autonomy model (manual to fully autonomous) mapped to human-in-the-loop roles and risk-based trust thresholds. LLM "AI-Avatar" case study | Conceptual + case study | Emphasises explainability | Conceptual (SOC response) | Yes, conceptually (trust thresholds per autonomy level) | SOC-level framework. Not instantiated in an SDN controller or evaluated on network traffic |
| 15 | Bahashwan et al. | 2023 | A Systematic Literature Review on Machine Learning and Deep Learning Approaches for Detecting DDoS Attacks in Software-Defined Networking | Sensors | SLR of 70 primary studies (2014–2022) on ML/DL/hybrid DDoS detection in SDN | Survey | N/A | N/A | N/A | Scope is detection. Does not evaluate response/mitigation pipelines |
| 16 | Valdovinos et al. | 2021 | Emerging DDoS attack detection and mitigation strategies in software-defined networks: Taxonomy, challenges and future directions | J. Network and Computer Applications | Taxonomy of SDN DDoS detection and mitigation (ML, blockchain, honeynet, statistical, SDN-protocol-based) | Survey | N/A | Survey of mitigation | N/A | Predates XAI-integrated SDN work. Does not treat explainability as a mitigation criterion |

**Dataset note (CIC-DDoS2019):** The original CIC-DDoS2019 paper (Sharafaldin et al., 2019) is outside the 2020–2026 window and is deliberately **not** cited. We cite 2020+ papers that use the dataset instead: [2], [5], [10], [12]. For InSDN we cite the original 2020 paper [1]; [5] and [11] also use it.

---

## 2. Thematic Synthesis

**ML/DL detection in SDN is mature, and accuracy alone no longer differentiates.** The two surveys [15], [16] and the primary studies [2]–[5] show that classifying SDN traffic as benign or attack is a well-studied problem. Reported detection rates are routinely ≥ 99% (e.g., 99.2% in [5]; ≥ 99.9% in [11], [12]). Bahashwan et al. [15] report that ensemble, hybrid and single ML/DL models dominate the 70 studies they reviewed. Most work still evaluates offline on public datasets. InSDN [1] matters for our project because it was generated on a real SDN testbed (ONOS, Mininet/OVS) rather than a conventional network. However, its features come from CICFlowMeter, while a Ryu controller can only poll OpenFlow counters. This is why we collect our own Mininet/OVS flow-stats data and use InSDN as a cross-check rather than as training data that maps directly onto controller features. Chouhan et al. [4] and Alashhab et al. [5] are the closest "live Ryu" precedents. Both extract features from controller-observed traffic, and [5] also uses InSDN and CIC-DDoS2019 for benchmarking.

**Explainability work on IDS is strong, but almost all of it is offline and analyst-facing.** Wang et al. [7] introduced SHAP local and global explanations for IDS (on NSL-KDD). Gaspar et al. [9] showed that LIME and SHAP explanations can be validated by perturbing the top-ranked features, and that explanations increase user trust. Neupane et al. [8] survey the X-IDS field, propose a human-in-the-loop architecture, and say that defining and measuring explanation quality is an open problem. Alquliti et al. [13] take this up with "feature alignment" metrics, which score explanations by how well they match domain-knowledge feature sets for each attack type. This is conceptually the same as our "explanation consistency with the attack's expected signature" check, except that [13] uses it only as an offline evaluation metric. In the SDN context specifically, [10], [11] and [12] apply SHAP (and LIME in [11]) to XGBoost or Random Forest SDN detectors. Only [12] describes a Ryu-based control loop, and even there SHAP output is "appended to alert payloads for operator triage". It does not influence whether a rule is installed.

**Automated mitigation in SDN controllers exists, but it is usually triggered directly by the label.** Novaes et al. [2] (Floodlight), Tan et al. [3] and Alashhab et al. [5] (Ryu) close the loop from detection to mitigation. Tan et al. [3] add a data-plane trigger as a first-stage filter before ML classification, a two-stage check that reduces unnecessary actions. Novaes et al. [2] use a dynamic statistical threshold plus fuzzy rules. El Kamel et al. [6] are the most relevant to *graduated* response. They argue that uniform rate limiting penalises benign and malicious hosts alike and produces false positives. Their alternative is per-host weights, trust scores and temporary (time-bounded) blocking. Our "meter rate-limit before DROP, with hard_timeout auto-expiry" escalation follows the same idea. The difference is that our escalation is driven by explicit classifier confidence and persistence over windows, not by learned DNN weights.

**Confidence and trust gating are discussed mostly outside SDN.** The clearest articulation of "act automatically only when trust conditions hold" comes from SOC research. Mohsin et al. [14] map five autonomy levels to human-in-the-loop roles and risk-based trust thresholds. Neupane et al. [8] also advocate human-in-the-loop X-IDS. Within the SDN papers we reviewed, gating is at most a single threshold (τ = 0.70 in [12]), a statistical anomaly threshold ([2]), a two-stage pre-filter ([3]), or a trust score ([6]). None of them combine classifier probability, temporal persistence, explanation consistency and an asset whitelist into one policy that must pass before a rule is installed.

**Operational cost of explanations is a practical constraint.** XAI-SDN [12] measures that computing SHAP for every flow cuts throughput by roughly 31× (about 60.6k to about 1.95k flows/s). This supports a design that explains only the windows the classifier has already flagged, so TreeExplainer runs once per alert rather than once per flow. A tree ensemble (RF/XGBoost) is also the model family for which exact TreeSHAP is cheapest. This matches the model choice in [10], [11] and [12].

---

## 3. Research Gaps Addressed by Our Design

Each gap below is limited to what the reviewed papers actually report. We do not claim that no paper anywhere does these things, only that none of the reviewed 2020–2026 works do.

- **RG1: Explanations do not drive SDN mitigation decisions.** SDN XAI works either stop at offline explanation ([10], [11]) or, in the one controller-oriented design [12], attach SHAP values to alerts for human triage while the drop decision depends only on the classifier threshold. **Our design** uses the SHAP explanation as an input to the mitigation policy (an explanation-consistency check) as well as to the audit log.

- **RG2: No multi-condition "safety gate" before rule installation in SDN.** Controller-integrated systems act on a label, a single threshold, or a statistical/fuzzy anomaly score ([2], [3], [5], [12]), and trust-scored rate limiting [6] does not use explanations or asset criticality. Trust thresholds and human-in-the-loop autonomy levels exist conceptually for SOCs [8], [14] but are not implemented in an SDN controller. **Our design** installs mitigation only if probability ≥ threshold, the alert persists over *k* consecutive windows, the explanation matches the attack's expected feature signature, and the target is not on a protected whitelist.

- **RG3: Explanation quality is evaluated offline, not used at runtime.** Feature-alignment metrics [13] and perturbation-based validation [9] score explanations after the fact. Neupane et al. [8] identify explanation evaluation as an open problem. **Our design** turns the alignment idea into a per-alert runtime check: when the top SHAP features disagree with the predicted class's signature, the alert is downgraded to "alert-only" instead of being mitigated.

- **RG4: Graduated, self-expiring response tied to confidence is rare.** Most mitigation designs block or drop ([3], [5], [12]). El Kamel et al. [6] show why uniform rate limiting is problematic and use temporary blocking, but their escalation is not tied to classifier confidence or explanation. **Our design** escalates alert, then OpenFlow meter rate-limit, then DROP with `hard_timeout`, so that a false positive costs at most a bounded, self-healing degradation.

- **RG5: SDN XAI studies are binary/offline and rarely multi-class with controller-native features.** [12] is binary (SYN only) and offline. [10] is offline on CIC-DDoS2019. [11] is multi-class but offline on CICFlowMeter-feature datasets (InSDN, CIC-IDS2017). **Our design** trains a multi-class model (benign, ICMP/SYN/UDP flood, port scan) on features computed from OpenFlow flow-stats polled by Ryu in Mininet/OVS, and uses InSDN [1] as a cross-dataset sanity check.

- **RG6: Explanation cost at line rate.** [12] reports a large throughput penalty for per-flow SHAP. **Our design** computes SHAP only for flagged per-source windows (on the order of one explanation per alert every ~2 s), and we will measure this overhead as part of our evaluation.

---

## 4. References (IEEE style)

[1] M. S. Elsayed, N.-A. Le-Khac, and A. D. Jurcut, "InSDN: A novel SDN intrusion dataset," *IEEE Access*, vol. 8, pp. 165263–165284, 2020, doi: 10.1109/ACCESS.2020.3022633.

[2] M. P. Novaes, L. F. Carvalho, J. Lloret, and M. L. Proença Jr., "Long short-term memory and fuzzy logic for anomaly detection and mitigation in software-defined network environment," *IEEE Access*, vol. 8, pp. 83765–83781, 2020, doi: 10.1109/ACCESS.2020.2992044.

[3] L. Tan, Y. Pan, J. Wu, J. Zhou, H. Jiang, and Y. Deng, "A new framework for DDoS attack detection and defense in SDN environment," *IEEE Access*, vol. 8, pp. 161908–161919, 2020, doi: 10.1109/ACCESS.2020.3021435.

[4] R. K. Chouhan, M. Atulkar, and N. K. Nagwani, "A framework to detect DDoS attack in Ryu controller based software defined networks using feature extraction and classification," *Applied Intelligence*, vol. 53, no. 4, pp. 4268–4288, 2023 (published online Jun. 2022), doi: 10.1007/s10489-022-03565-6.

[5] A. A. Alashhab, M. S. Zahid, B. Isyaku, A. A. Elnour, W. Nagmeldin, A. Abdelmaboud, T. A. A. Abdullah, and U. D. Maiwada, "Enhancing DDoS attack detection and mitigation in SDN using an ensemble online machine learning model," *IEEE Access*, vol. 12, pp. 51630–51649, 2024, doi: 10.1109/ACCESS.2024.3384398.

[6] A. El Kamel, H. Eltaief, and H. Youssef, "On-the-fly (D)DoS attack mitigation in SDN using deep neural network-based rate limiting," *Computer Communications*, vol. 182, pp. 153–169, Jan. 2022, doi: 10.1016/j.comcom.2021.11.003.

[7] M. Wang, K. Zheng, Y. Yang, and X. Wang, "An explainable machine learning framework for intrusion detection systems," *IEEE Access*, vol. 8, pp. 73127–73141, 2020, doi: 10.1109/ACCESS.2020.2988359.

[8] S. Neupane, J. Ables, W. Anderson, S. Mittal, S. Rahimi, I. Banicescu, and M. Seale, "Explainable intrusion detection systems (X-IDS): A survey of current methods, challenges, and opportunities," *IEEE Access*, vol. 10, pp. 112392–112415, 2022, doi: 10.1109/ACCESS.2022.3216617.

[9] D. Gaspar, P. Silva, and C. Silva, "Explainable AI for intrusion detection systems: LIME and SHAP applicability on multi-layer perceptron," *IEEE Access*, vol. 12, pp. 30164–30175, 2024, doi: 10.1109/ACCESS.2024.3368377.

[10] Z. Raihan and S. Islam, "Enhancing transparency in DDoS detection on SDN using explainable ML models," in *Proc. 2024 2nd Int. Conf. Information and Communication Technology (ICICT)*, Dhaka, Bangladesh, Oct. 2024, pp. 76–80, doi: 10.1109/ICICT64387.2024.10839660.

[11] M. T. H. Saykat, M. E. Haque, F. A. Farid, R. Hossen, J. Uddin, and H. B. A. Karim, "An efficient and interpretable intrusion detection framework for software-defined networks with multi-class imbalanced data using genetic and GAN-based optimization," *Scientific Reports*, vol. 16, Art. no. 21406, Jul. 2026, doi: 10.1038/s41598-026-58514-x.

[12] A. Ahmad, A. Akarma, A. Ali, H. Muneer, and T. A. Syed, "XAI-SDN: An explainable entropy-guided machine learning framework for real-time DDoS detection in software defined networks," arXiv preprint arXiv:2609.05701, Sep. 2026, doi: 10.48550/arXiv.2609.05701.

[13] M. Alquliti, E. Karafili, and B. Kang, "Evaluating explanation quality in X-IDS using feature alignment metrics," arXiv preprint arXiv:2505.08006, May 2025, doi: 10.48550/arXiv.2505.08006.

[14] A. Mohsin, H. Janicke, A. Ibrahim, I. H. Sarker, and S. Camtepe, "A unified framework for human–AI collaboration in security operations centers with trusted autonomy," *ACM Transactions on Internet Technology*, vol. 26, no. 4, pp. 1–34, 2026, doi: 10.1145/3837073.

[15] A. A. Bahashwan, M. Anbar, S. Manickam, T. A. Al-Amiedy, M. A. Aladaileh, and I. H. Hasbullah, "A systematic literature review on machine learning and deep learning approaches for detecting DDoS attacks in software-defined networking," *Sensors*, vol. 23, no. 9, Art. no. 4441, 2023, doi: 10.3390/s23094441.

[16] I. A. Valdovinos, J. A. Pérez-Díaz, K.-K. R. Choo, and J. F. Botero, "Emerging DDoS attack detection and mitigation strategies in software-defined networks: Taxonomy, challenges and future directions," *Journal of Network and Computer Applications*, vol. 187, Art. no. 103093, Aug. 2021, doi: 10.1016/j.jnca.2021.103093.

---

## 5. Verification Notes

For each reference, the bibliographic metadata (title, authors, venue, volume, pages, year) was cross-checked against the Crossref record for the DOI (`https://api.crossref.org/works/<DOI>`). For arXiv preprints the arXiv API/abstract page was used. A second publisher, indexing or repository page was also consulted, as listed below. Claims in the table come from the abstracts and from the descriptions on these pages.

| # | Primary verification URL | Additional URL(s) consulted |
|---|---|---|
| 1 | https://api.crossref.org/works/10.1109/ACCESS.2020.3022633 | https://ui.adsabs.harvard.edu/abs/2020IEEEA...8p5263E/abstract ; https://www.researchgate.net/publication/344206268_InSDN_A_Novel_SDN_Intrusion_Dataset |
| 2 | https://api.crossref.org/works/10.1109/ACCESS.2020.2992044 | https://ieeexplore.ieee.org/document/9085352/ ; Semantic Scholar API (abstract) |
| 3 | https://api.crossref.org/works/10.1109/ACCESS.2020.3021435 | Semantic Scholar API record (abstract; open-access IEEE PDF link https://ieeexplore.ieee.org/ielx7/6287639/8948470/09186014.pdf) |
| 4 | https://api.crossref.org/works/10.1007/s10489-022-03565-6 | https://link.springer.com/article/10.1007/s10489-022-03565-6 ; https://www.researchgate.net/publication/361154152 |
| 5 | https://api.crossref.org/works/10.1109/ACCESS.2024.3384398 | https://squ.elsevierpure.com/en/publications/enhancing-ddos-attack-detection-and-mitigation-in-sdn-using-an-en/ ; Semantic Scholar API (abstract) |
| 6 | https://api.crossref.org/works/10.1016/j.comcom.2021.11.003 | https://www.sciencedirect.com/science/article/abs/pii/S0140366421004308 ; https://www.semanticscholar.org/paper/266fb307be159874b65da8bbd9031eb87e7ed898 |
| 7 | https://api.crossref.org/works/10.1109/ACCESS.2020.2988359 | https://ieeexplore.ieee.org/abstract/document/9069273/ |
| 8 | https://api.crossref.org/works/10.1109/ACCESS.2022.3216617 | https://arxiv.org/abs/2207.06236 ; https://ui.adsabs.harvard.edu/abs/2022IEEEA..10k2392N/abstract |
| 9 | https://api.crossref.org/works/10.1109/ACCESS.2024.3368377 | https://ieeexplore.ieee.org/document/10440604/ ; https://ui.adsabs.harvard.edu/abs/2024IEEEA..1230164G/abstract |
| 10 | https://api.crossref.org/works/10.1109/ICICT64387.2024.10839660 | https://www.researchgate.net/publication/388265044 ; Semantic Scholar API (abstract) |
| 11 | https://api.crossref.org/works/10.1038/s41598-026-58514-x | https://pmc.ncbi.nlm.nih.gov/articles/PMC13350713/ ; https://www.nature.com/articles/s41598-026-58514-x |
| 12 | https://arxiv.org/abs/2609.05701 | https://arxiv.org/html/2609.05701 ; arXiv API (export.arxiv.org) |
| 13 | https://arxiv.org/abs/2505.08006 | arXiv API (export.arxiv.org) |
| 14 | https://api.crossref.org/works/10.1145/3837073 | https://arxiv.org/abs/2505.23397 (journal-ref: ACM TOIT, DOI 10.1145/3837073) |
| 15 | https://api.crossref.org/works/10.3390/s23094441 | https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10181661/ |
| 16 | https://api.crossref.org/works/10.1016/j.jnca.2021.103093 | https://www.sciencedirect.com/science/article/abs/pii/S1084804521001156 ; https://www.semanticscholar.org/paper/a19a277f3faafa21d74aa0ae9534afd7d96d611a |

**Caveats to keep in mind when citing:**
- [4] carries a 2023 volume year (vol. 53, no. 4) but appeared online in June 2022. Some indexes list issue 7 instead of 4. Crossref and Springer give issue 4.
- [12] and [13] are preprints (not peer-reviewed). [12] was posted 4 Sep 2026.
- [14] has been on arXiv since May 2025. The ACM TOIT version is vol. 26, no. 4 (2026).
- Descriptions of [3], [5], [6] and [10] are based on abstracts and publisher summaries, because full texts were paywalled or blocked to automated retrieval. Before you write detailed claims about their internals (e.g., exact mitigation rules), read the full PDFs through your institution's library.

**Verified but not included (to stay within 12–16 papers); you can swap them in:**
- J. C. Correa Chica, J. C. Imbachi, J. F. Botero Vega, "Security in SDN: A comprehensive survey," *J. Netw. Comput. Appl.*, vol. 159, Art. no. 102595, 2020, doi: 10.1016/j.jnca.2020.102595.
- M. S. Elsayed, N.-A. Le-Khac, S. Dev, A. D. Jurcut, "DDoSNet: A deep-learning model for detecting network attacks," in *Proc. IEEE WoWMoM 2020*, pp. 391–396, doi: 10.1109/WoWMoM49955.2020.00072 (uses CIC-DDoS2019 in an SDN context).
- A. A. Najar, S. M. Naik, "Cyber-Secure SDN: A CNN-based approach for efficient detection and mitigation of DDoS attacks," *Computers & Security*, vol. 139, Art. no. 103716, 2024, doi: 10.1016/j.cose.2024.103716.
- C. S. Kalutharage, X. Liu, C. Chrysoulas, N. Pitropakis, P. Papadopoulos, "Explainable AI-based DDOS attack identification method for IoT networks," *Computers*, vol. 12, no. 2, Art. no. 32, 2023, doi: 10.3390/computers12020032.
- T. E. Ali, Y.-W. Chong, S. Manickam, "Machine learning techniques to detect a DDoS attack in SDN: A systematic review," *Applied Sciences*, vol. 13, no. 5, Art. no. 3183, 2023, doi: 10.3390/app13053183.
- L. F. Eliyan, R. Di Pietro, "DoS and DDoS attacks in Software Defined Networks: A survey of existing solutions and research challenges," *Future Gener. Comput. Syst.*, vol. 122, pp. 149–171, 2021, doi: 10.1016/j.future.2021.03.011.
