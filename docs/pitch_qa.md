# NetSentinel Pitch Q&A Preparation Sheet

> **Audience:** Microsoft Innovate 2026 Technical Judges & SOC Leaders
> **Alignment:** M5-08 Q&A Preparation
> **Format:** Crisp 15–20s Spoken Answer $\to$ Deep Technical Backup $\to$ Exact Repo Citation $\to$ Honest Boundary
> **Guiding Principle:** *Defend measured facts; never invent unsupported capabilities.*

---

## Question 1: "It's supervised. How does it catch novel attacks?"

### 15–20 Second Spoken Answer
> *"We don't rely on pure unsupervised anomaly detectors—we proved on 45 million flows that benign-only Isolation Forests fail with near-zero recall at usable false-alarm rates. Instead, our supervised binary forest generalises on behavioral flood and C2 mechanics, while our multi-class head's low confidence marks unfamiliar variants as novel anomalies with an ROC-AUC of 0.997 to 1.000."*

### Deep Technical Backup
- **The Empirical Discovery (ADR-1):** In early experiments (`docs/experiments.md` §4), we trained an Isolation Forest exclusively on benign traffic. Tested on CSE-CIC-IDS2018, it achieved ROC-AUC of only 0.70–0.87 and near-zero recall at a workable benign false-alarm rate ($0.1\%$).
- **Dual-Head Gating Architecture:**
  1. The binary Random Forest (`rf_binary`) evaluates $P(\text{attack})$. Because it learns structural network flow anomalies (packet length variance, inter-arrival deviations, TCP window states), it generalises to unseen attack families.
  2. The multi-class family head (`rf_multiclass`) evaluates probabilities $P(f \mid \text{attack})$ across known families. If max probability $f_{\text{conf}} < \tau_{\text{family}}$, the flow is gated to `Verdict.NOVEL_ANOMALY` with `AttackFamily.UNKNOWN`.
- **Leave-One-Attack-Out (LOAO) Evidence:** In controlled leave-one-out experiments across 3 seeds on held-out test splits:
  - When DDoS floods are held out of training, the model still detects **99.8%** of flows.
  - When endpoint DoS is held out, it detects **99.1%**.
  - When the Ares botnet is held out, it detects **66%** at 0.1% FPR and **99%** at 0.5% FPR.
  - On LUFlow, the forest flags ~100% of the unexplained `outlier` honeypot traffic.

### Repository Citations
- [docs/experiments.md §4–§5](experiments.md#4-the-unsupervised-experiment-benign-only-isolation-forest) (Unsupervised vs Supervised measurements)
- [docs/03_architecture.md §9 ADR-1](03_architecture.md#9-key-decisions-short-adrs) (Decision Record on Novelty Architecture)
- [docs/model_card.md §3 & §4](model_card.md#3-leave-one-attack-out-loao-the-novel-attack-test) (LOAO Benchmark Table)

### Honest Boundary
- The model generalises robustly to volumetric floods, DoS, and botnet command-and-control.
- **Where it does NOT generalise:** Slow internal Nmap port scans and the `LOIC-HTTP` tool are missed when held out entirely from training at strict budgets (recall $\approx 1\%$). Furthermore, SSH brute force is knife-edge below 0.1% FPR (0% to 74% across seeds at 0.05% FPR). We state this limitation openly.

---

## Question 2: "What if the model is wrong?"

### 15–20 Second Spoken Answer
> *"That is precisely why NetSentinel enforces a strict 'Alert SOC, Never Auto-Block' policy. Misclassifications never trigger automated firewall drops that could take down production services. Every alert provides fast TreeSHAP feature deviations against normal baselines and confidence-hedged briefings so analysts can verify true positives in seconds, and the console is designed to capture analyst confirmation/dismissal and track verified precision."*

### Deep Technical Backup
- **Operational Safety Mandate:** Automatic inline blocking based on statistical machine learning introduces unacceptable risk of self-inflicted denial-of-service. NetSentinel is an alert prioritisation and explainability layer, not an inline firewall.
- **Fast Explainability for Rapid Verification:** When an analyst clicks an incident, TreeSHAP decomposes the binary prediction into the top 5 feature contributions in ~50–110 ms, displaying raw values alongside benign training medians from `baseline_stats.json` (e.g. *"flow duration is 35 µs vs median 61,844 µs"*).
- **Confidence-Band Hedging:** Low-confidence alerts ($< 0.60$) are explicitly hedged as *"Possible"* or *"Worth reviewing before escalating"*, actively warning the analyst against premature action.
- **Closed-Loop Feedback:** The console interface is designed with `confirm` and `dismiss_fp` actions, structured to capture analyst feedback and track the `Analyst-Confirmed Precision` metric (`/v1/metrics`) to maintain transparent operational accountability.

### Repository Citations
- [docs/03_architecture.md §1 & §4.4](03_architecture.md#1-system-overview) (Core Principles & Risk Scoring)
- [docs/threat_model.md §4](threat_model.md#4-role-of-explainability-shap-vs-risk-scoring) (Decoupling SHAP from Risk)
- [api/app/services/brief.py](../api/app/services/brief.py) (Confidence-Band Hedging Implementation)

### Honest Boundary
- A human must review the incident card. If the SOC is completely unstaffed, NetSentinel logs and prioritises the incident in the database, but does not take unilateral containment actions.

---

## Question 3: "Isn't this just lab data?"

### 15–20 Second Spoken Answer
> *"We deliberately test on two datasets for two different jobs. CSE-CIC-IDS2018 is our controlled benchmark with audited multi-class labels, but we prove real-world viability by training and serving a separate model on Lancaster University's LUFlow—unscripted internet honeypot traffic collected across 2020 and 2021 that exhibits authentic temporal drift."*

### Deep Technical Backup
- **Two Datasets, Two Jobs (ADR-8):**
  1. **CSE-CIC-IDS2018 (Audited & Corrected Release):** 45.2M clean flows across 420 machines, 30 servers, and 50 attackers. Used for supervised training, multi-class attribution, and Leave-One-Attack-Out holdouts.
  2. **LUFlow (Lancaster University Honeypots):** 44.9M clean flows across 72 capture days from 2020-06 through 2021-02. Real internet background traffic and autonomous scanning bots, labelled via live threat intelligence.
- **Empirical LUFlow Performance:** Tested across 7 later months with a frozen model:
  - Binary recall: **99.8% – 99.9%**.
  - Benign false-alarm rate: **0.17% – 0.71%** against a 0.5% budget.
  - ROC-AUC: **1.000**.
  - Novelty capture: Flags ~100% of unexplained `outlier` flows.

### Repository Citations
- [docs/03_architecture.md §3.0 & §9 ADR-8](03_architecture.md#30-datasets-two-datasets-two-jobs) (Dataset Rationale)
- [docs/model_card.md §1.1 & §4](model_card.md#11-datasets-and-why) (Dataset Details & LUFlow Evaluation)
- [data/README.md](../data/README.md) (Audited Flow Counts & Cleaning Reports)

### Honest Boundary
- LUFlow attack labels come from threat intelligence feeds matching known malicious IPs; it lacks fine-grained multi-class family tags. Therefore, the LUFlow model operates in binary mode (`AttackFamily.MALICIOUS` and `Verdict.NOVEL_ANOMALY`) rather than multi-class attribution.
- Scripted 2018 benign traffic lacks real-world drift; LUFlow provides that missing validation.

---

## Question 4: "Why 2018 and not older datasets like NSL-KDD or 2017?"

### 15–20 Second Spoken Answer
> *"The problem statement lists older datasets only as examples. NSL-KDD is from 1999 and completely unrepresentative of modern networks. CICIDS2017 has severe label corruption and lacks sufficient rare-class support. We selected the corrected 2018 release by Liu and Engelen because it models a modern 420-node AWS network, includes modern tools like HOIC, and fixes the fatal packet-extractor bugs."*

### Deep Technical Backup
- **Why Not NSL-KDD / KDD99?** 25-year-old traffic generated on simulated Unix operating systems with obsolete protocols; irredeemably outdated.
- **Why Not Original CICIDS2017 / Original 2018?** Liu, Engelen et al. (IEEE CNS 2022) proved that the original CICFlowMeter extractor had severe implementation bugs: inverted flow directions, negative TCP header lengths, and shifted attack labels. Furthermore, the original 2018 CSVs lacked IP address columns on most days, making incident correlation impossible.
- **The Corrected Release (Liu/Engelen et al., CNS 2022):** Re-extracted 63M raw flows from raw PCAPs with fixed flow generators, verified UTC timestamps, preserved `Src IP` and `Dst IP`, and audited attack labels.
- **Infrastructure Diversity:** 420 internal hosts, 30 enterprise servers across multiple subnets, and modern attack tooling (LOIC-UDP, HOIC, Hulk, GoldenEye, Ares botnet).

### Repository Citations
- [docs/03_architecture.md §9 ADR-8](03_architecture.md#9-key-decisions-short-adrs) (Dataset Selection ADR)
- [docs/data_profile.md §1 & §3](data_profile.md#1-the-two-datasets-measured-facts-not-assumptions) (Measured Facts on Corrected 2018)
- [docs/01_problem_analysis.md §3](01_problem_analysis.md#3-the-two-datasets-and-why-they-differ) (Dataset Comparison)

### Honest Boundary
- Even in corrected 2018, all FTP-Patator flows are closed port attempts (`Attempted Category != -1`, relabelled BENIGN), SlowHTTPTest is absent, and WebAttack has only 283 clean flows. We document these quirks explicitly.

---

## Question 5: "How is risk computed?"

### 15–20 Second Spoken Answer
> *"Risk separates certainty from consequence. Confidence measures model certainty, but severity measures real-world damage—from 0.3 for a harmless port scan to 1.0 for an internal infiltration. We multiply confidence by expected severity and a logarithmic burst factor, ensuring that dangerous breaches and high-volume storms immediately jump to the top of the queue."*

### Deep Technical Backup
- **The Core Risk Formula (`nscore/contracts/policy.py`):**
  $$\text{severity} = \sum_{f} P(f \mid \text{attack}) \times W[f]$$
  $$\text{burst\_factor}(\text{flow\_count}) = 1 + 0.15 \times \min\left(1.0, \frac{\log_{10}(\max(\text{flow\_count}, 1))}{3}\right)$$
  $$\text{risk\_score} = \text{round}\left(100 \times \min\left(1.0, \text{confidence} \times \text{severity} \times \text{burst\_factor} + \text{novelty\_bonus}\right)\right)$$
- **Expected Severity:** Avoids arbitrary step-function cliff edges. If a classifier is split 50/50 between `WebAttack` (0.6) and `Infiltration` (1.0), expected severity evaluates to exactly `0.80`.
- **Logarithmic Burst Multiplier:** Single flow gives $1.00$; 10 flows gives $1.05$; 100 flows gives $1.10$; $\ge 1,000$ flows caps at $1.15$.
- **Severity Lookup Hierarchy:**
  - `Infiltration` ($1.00$): Attacker already inside internal subnet.
  - `Botnet` ($0.90$): Active endpoint host compromise and C2 beaconing.
  - `DDoS` / `DoS` ($0.80$): Immediate service disruption and availability outage.
  - `BruteForce` / `Malicious` ($0.70$): Active attempt to gain access or verified malicious feed.
  - `WebAttack` ($0.60$): Public exploit probe, frequently stopped by WAF.
  - `PortScan` ($0.30$): External reconnaissance probing only; zero compromise.

### Repository Citations
- [nscore/contracts/policy.py](../nscore/contracts/policy.py) (Production Code Implementation)
- [docs/threat_model.md §3 & §5](threat_model.md#3-the-netsentinel-risk-scoring-engine-certainty-vs-consequence) (Full Weight Defense & Rationale)
- [tests/test_contracts.py](../tests/test_contracts.py) (Automated Test Parity)

### Honest Boundary
- Weights are expert policy baselines assigned by security engineering analysis. They are intentionally kept in an accessible configuration dictionary (`SEVERITY`) so enterprise SOC managers can tune them to match their asset criticality without modifying ML code.

---

## Question 6: "Can you really maintain 1% FPR at scale?"

### 15–20 Second Spoken Answer
> *"We do not claim that 1% FPR is sufficient at enterprise scale. On a 420-host network handling 330,000 benign flows an hour, a 1% false-alarm rate generates over 3,000 false alarms every hour. That is why we calibrated our operating threshold to a strict 0.1% benign FPR budget and added an incident correlator to collapse repeated flows into single incidents."*

### Deep Technical Backup
- **The Scale Problem (ADR-10):** In early planning, we considered a 1% false-alarm rate. At real enterprise prevalence (where attacks represent under 5% of flows), a 1% FPR cuts precision from 99.9% down to 87%, creating thousands of false alerts per hour.
- **Operating Curve Calibration:** We calibrated `tau_binary` against a strict **0.1% benign false-alarm budget** on validation traffic.
- **Test Set Reality Check:** On the unseen test split, the empirical benign FPR measured at **0.20%** (approximately $2\times$ the validation budget target).
- **Incident Correlator as Volume Reducer:** The correlator groups flows within a 5-minute sliding window on `(src_ip, dst_ip, attack_family)`. Replaying 10,000 flows of a DDoS storm produces **exactly 1 incident**.

### Repository Citations
- [docs/03_architecture.md §9 ADR-10 & §4.3](03_architecture.md#9-key-decisions-short-adrs) (0.1% Operating Budget Rationale)
- [docs/experiments.md §6](experiments.md#6-threshold-calibration--operating-curves) (Operating Curves Table)
- [docs/model_card.md §7 item 3 & 4](model_card.md#7-limitations-and-failure-modes) (Documented Scale Limitations)

### Honest Boundary
- Even at 0.1% FPR, an uncorrelated flow stream generates hundreds of false alerts per hour. NetSentinel relies heavily on the Incident Correlator to group these into manageable incidents. We do not claim zero false positives.

---

## Question 7: "How do you detect drift?"

### 15–20 Second Spoken Answer
> *"We compute Population Stability Index across top features over a rolling 2,000-flow window against training reference baselines. On real LUFlow honeypot traffic, we measured PSI crossing 0.25 on later months, triggering an alert in the drift-monitor workflow that recommends label-free recalibration on recent benign traffic."*

### Deep Technical Backup
- **Drift Sensor Math (`nscore/drift/psi.py`):**
  $$\text{PSI} = \sum_{b=1}^{B} (P_b - Q_b) \times \ln\left(\frac{P_b + \epsilon}{Q_b + \epsilon}\right)$$
  Quantile bins ($B=10$) for top-15 features are precomputed on clean training traffic and packaged into `drift_reference.json`.
- **Operational Thresholds:**
  - $\text{PSI} < 0.10$: `Status: OK` (Green).
  - $0.10 \le \text{PSI} < 0.25$: `Status: WATCH` (Amber).
  - $\text{PSI} \ge 0.25$: `Status: ALERT` (Red banner recommending recalibration).
- **Empirical Validation on LUFlow (7 Later Months):** Max PSI measured by month:
  - 2020-06: 0.14 (`watch`) | 2020-07: **0.39 (`alert`)** | 2020-08: 0.20 (`watch`)
  - 2020-09: 0.14 (`watch`) | 2020-10: 0.10 (`watch`) | 2020-11: 0.18 (`watch`)
  - 2020-12: **0.36 (`alert`)** | 2021-01: 0.12 (`watch`) | 2021-02: 0.10 (`watch`)
- **Recalibration, honestly:** `luflow-recal` refits the thresholds and Isolation Forest on an unlabelled recent benign window. It does not change PSI (drift is measured against the training reference) and on LUFlow it did not improve detection, so the demo shows the ALERT and the fact that detection held, not a recovery.

### Repository Citations
- [nscore/drift/psi.py](../nscore/drift/psi.py) (PSI Implementation)
- [docs/03_architecture.md §4.6](03_architecture.md#46-drift-monitor) (Drift Service Architecture)
- [docs/model_card.md §5](model_card.md#5-drift) (Measured Monthly PSI Results)

### Honest Boundary
- While PSI accurately detected feature distribution drift in July and December 2020, model recall and FPR on LUFlow did not significantly degrade during those months. Therefore, PSI operates as an **early warning light** that input distributions shifted, rather than a direct measurement of accuracy collapse.

---

## Bonus Question 8: "Why not just use an LLM directly to analyze raw packets?"

### 15–20 Second Spoken Answer
> *"High-speed enterprise networks process millions of flows per minute. Large language models cost thousands of times more compute, introduce 1–3 seconds of latency per flow, and cannot process raw binary packets at line rate. We use Random Forests for sub-millisecond flow scoring and reserve Azure OpenAI strictly for human-speed 3-sentence incident summaries."*

### Deep Technical Backup
- **Line-Rate Constraints:** NetSentinel scores batches of 500 flows in under 15 milliseconds. Sending raw network flows to an LLM would cost thousands of dollars per hour, bottleneck line rate, and violate enterprise privacy by sending internal packet headers off-premises.
- **Architectural Separation:** Fast, deterministic scikit-learn models evaluate flows; TreeSHAP extracts structured features; and Azure OpenAI drafts human briefings only when an analyst inspects an incident.

---

## Bonus Question 9: "Why Random Forests instead of Deep Learning or Graph Networks?"

### 15–20 Second Spoken Answer
> *"Tabular flow features are dominated by non-linear threshold cutoffs—like packet length and inter-arrival time ratios—where tree ensembles consistently outperform deep networks. Furthermore, Random Forests evaluate in sub-milliseconds on standard CPUs, allow exact TreeSHAP attribution, and remain portable across edge environments without GPU dependencies."*

### Deep Technical Backup
- **Tabular Data Benchmarks:** Peer-reviewed tabular ML research (e.g. Grinsztajn et al., NeurIPS 2022) demonstrates that tree-based ensembles routinely outperform deep learning and MLPs on tabular datasets with irregular distributions.
- **Explainability Guarantees:** TreeSHAP provides exact, polynomial-time Shapley value calculations ($O(T L D^2)$) for trees, whereas neural network explainers require expensive, noisy sampling approximations.
- **Zero GPU Overhead:** NetSentinel packages models in tiny ~5 MB joblib bundles that run on lightweight cloud containers or standard SOC laptops.
