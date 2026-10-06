# Microsoft Innovate 2026 — Round 1 Idea Submission

**Problem Statement Title:** #26 — Catch the Attack the Signatures Miss
**Theme / Bucket:** Cybersecurity — Security Operations
**Team Name:** NetSentinel
**Document Status:** Revised & Verified (incorporates validation fixes A1–A12 from `docs/02_doc_validation.md`)

---

## 1. Team Details

| S. No. | Full Name | Role in Team | Track Ownership |
|:---:|---|---|---|
| 1 | Track Lead (M1) | Data & Features Specialist | `ml/data/`, feature extraction, drift monitoring |
| 2 | Track Lead (M2) | ML Modeling & MLOps | `ml/train/`, evaluations, Azure ML registry |
| 3 | Track Lead (M3) | Backend & Platform Engineer | `api/` (FastAPI), database, correlator engine |
| 4 | Track Lead (M4) | SOC Console Developer | `dashboard/` (Streamlit SOC Console) |
| 5 | Track Lead (M5) | Security, GenAI & Storytelling | Risk engine, GenAI briefs, replay & evaluation |

---

## 2. Problem Statement

### What is the problem?
1. **Signature-Based IDS Blindness:** Traditional intrusion detection systems (such as Snort and Suricata) match incoming network packets strictly against static, known attack signatures. In an independent empirical study across 356 real-world zero-day exploits, Snort successfully detected **only 17%** of attacks—missing approximately 83% of zero-day attacks ([Holm, HICSS 2014](https://dl.acm.org/doi/10.1109/HICSS.2014.600)).
2. **Acute SOC Alert Fatigue:** In high-throughput network environments, security operations centres are overwhelmed by flat, unweighted alert floods. Contemporary enterprise studies reveal that **46% of all alerts received by SOC analysts are false positives** (Microsoft / Omdia, *State of the SOC Report*, 2026).
3. **Flat Severity Queues:** Traditional NIDS score alerts by signature match rather than operational consequence. A noisy, harmless external port scan generates thousands of high-priority alerts, while a stealthy, low-volume internal lateral compromise is buried at the bottom of the queue.

### Who faces it?
- Tier-1 and Tier-2 SOC analysts at enterprise security teams, Managed Security Service Providers (MSSPs), cloud providers, and financial institutions.
- Alert queues refill continuously around the clock; analysts suffer severe cognitive overload and burnout, directly increasing mean time to acknowledge (MTTA) and detect (MTTD).

### Why do current options fall short?
- **Signature IDS & SIEM Rules:** Both require pre-existing attack patterns or rule definitions to fire. Unknown exploit variants, polymorphic payloads, and novel zero-day techniques slip through unnoticed.
- **Black-Box ML Detectors:** Academic anomaly detectors often produce uninterpretable alerts with high false-positive rates, destroying analyst trust.
- **Dangerous Auto-Blocking:** Automated inline blocking systems trigger operational self-denial-of-service when benign operational traffic is misclassified.

---

## 3. Proposed Solution

### Our Idea in One Line
> **NetSentinel is an explainable machine learning security layer that flags what signature IDS misses—delivering prioritised, explained SOC incidents, never an automated block.**

### How It Solves the Problem
1. **Dual-Head Flow Classification:**
   - **Stage 1 (Binary Head):** A compact Random Forest classifies bidirectional network flow records as normal vs. attack at calibrated operating false-alarm budgets (0.1% benign FPR).
   - **Stage 2 (Multi-Class Head):** Attributes attack traffic to known tactical families (`DoS`, `DDoS`, `BruteForce`, `Infiltration`, `Botnet`, `WebAttack`).
2. **Unfamiliar & Novel Anomaly Detection:**
   - Unfamiliar attack variants are surfaced when the binary model detects an attack but the multi-class head exhibits low confidence ($f_{\text{conf}} < \tau_{\text{family}}$), designating the flow as a **Novel Anomaly** (`Verdict.NOVEL_ANOMALY` / `AttackFamily.UNKNOWN`).
   - On unscripted real-world honeypot traffic (LUFlow), a benign-trained Isolation Forest provides complementary percentile anomaly detection against unmodelled outlier traffic.
3. **Incident Correlation & Consequence-Driven Risk Engine:**
   - **Incident Correlator:** Aggregates matching flows within a 5-minute sliding window keyed on `(src_ip, dst_ip, attack_family)`, collapsing 10,000-flow DDoS storms into a single actionable incident.
   - **Consequence-Driven Risk Math:**
     $$\text{Risk Score } = \text{round}\left(100 \times \left(\text{Confidence} \times \text{Expected Severity} \times \text{Burst Factor} + \text{Novelty Bonus}\right)\right)$$
     Separates statistical confidence (certainty) from damage potential (consequence). High-confidence port scans ($0.95 \times 0.30 = 28$ LOW) rank far below internal compromises ($0.81 \times 1.00 = 81$ HIGH).
4. **Transparent Explainability & Grounded GenAI Briefs:**
   - **Fast TreeSHAP Attribution:** Delivers top-5 feature attributions with comparisons to empirical benign training medians (~50–110 ms latency). Crucially, SHAP explains why an alert was flagged without altering the deterministic risk score.
   - **Azure OpenAI Incident Briefs:** Generates concise 3–4 sentence analyst summaries using `gpt-4o-mini` with strict confidence-band hedging, grounded only in structured incident fields, with an automatic 8-second SLA timeout and deterministic local template fallback.
5. **Strict "Alert SOC, Never Auto-Block" Mandate:**
   - Keeps the human in the loop. Incidents surface in an interactive SOC queue for Analyst Acknowledge, Escalate, Confirm, and Dismiss actions. Analyst feedback directly tracks verified precision.

---

## 4. Technical Approach & Architecture

### Enterprise Repository & Service Architecture
NetSentinel enforces a clean separation of concerns:
```
[ Raw Network Capture / PCAP ]
            │ (Offline fixed CICFlowMeter)
            ▼
[ Flow Records / Replay Engine ] ──> [ POST /v1/flows (FastAPI) ]
                                                │
                 ┌──────────────────────────────┴──────────────────────────────┐
                 ▼                                                             ▼
     [ FlowTransformer (nscore/) ]                                 [ Drift Monitor (PSI) ]
                 │                                                             │
                 ▼                                                             ▼
     [ Dual-Head Inference (RF) ]                                  [ Rolling 2,000 Flows ]
                 │
                 ├──> Low family confidence ──> Verdict: NOVEL_ANOMALY
                 ▼
     [ Incident Correlator (5-min Window) ]
                 │
                 ├───> [ TreeSHAP Explainer (Top-5 vs Baseline Medians) ]
                 ▼
     [ Risk Engine (policy.py: Severity x Conf x Burst) ]
                 │
                 ├───> [ Azure OpenAI Brief Service (8s SLA / Template Fallback) ]
                 ▼
     [ SQLite WAL Persistence & Audit Trail ]
                 │
                 ▼
     [ Streamlit SOC Console (Live Queue, Detail, Evaluation, Health) ]
```

### Planned Tech Stack
- **Frontend / Console:** Streamlit with Plotly visualizations (dark SOC console theme, live auto-refresh).
- **Backend API:** FastAPI (Python 3.11+, Pydantic v2 contract validation, async endpoints).
- **Persistence:** SQLite in WAL (Write-Ahead Logging) mode; portable with zero external database dependencies.
- **Machine Learning Core:** scikit-learn, imbalanced-learn, TreeSHAP, NumPy, Pandas, PyArrow.
- **Shared Monorepo Core (`nscore/`):** Shared feature transformation, risk policy, and contract schemas to prevent train/serve skew by construction.
- **Cloud & Enterprise Integration:**
  - **Azure Machine Learning:** Model registry storing versioned bundles with SHA256 integrity verification.
  - **Azure OpenAI Service:** Deploying `gpt-4o-mini` with system prompt grounding and 8-second SLA fallback.

---

## 5. Datasets & Empirical Grounding

To provide academic and operational credibility, NetSentinel rejects flawed legacy benchmarks and evaluates across two complementary datasets:

| Dataset | Role | Size & Scope | Why This Dataset |
|---|---|---|---|
| **CSE-CIC-IDS2018 (Audited & Corrected)** | Supervised Training, Validation & Benchmark Testing | 45.2M clean flows (after removing 18.0M duplicates); 46 pruned features | Large AWS enterprise network (420 machines, 30 servers, 50 attackers across 10 capture days). Corrected by Liu, Engelen et al. (IEEE CNS 2022) to resolve fatal label and flow-extractor bugs present in the original release. |
| **Lancaster University LUFlow** | Real-World Showcase & Temporal Drift Evaluation | 44.9M clean flows across 72 capture days (2020–2021) | Authentic internet attack traffic collected on production university honeypots. Reflects genuine unscripted temporal drift and provides real `outlier` traffic to evaluate novelty detection. |

---

## 6. What We Have Built & Feasibility Confirmation

1. **Contracts & Policy Engine Complete:** Shared schemas (`nscore/contracts/schemas.py`), deterministic risk engine (`policy.py`), and test fixtures verified against 50 passing unit tests.
2. **Feature Engineering & Adapter Pipeline:** Time-blocked 70/15/15 train/val/test splits with 60-second boundary purging (eliminating session leakage); Spearman $|\\rho| > 0.95$ correlation pruning reducing features to 46 interpretable predictors.
3. **Model & LOAO Validation:** Leave-One-Attack-Out (LOAO) experiments demonstrate that the supervised model robustly generalises to unseen attack families (DDoS floods, DoS, and botnets), while family-head confidence separates unfamiliar from familiar attacks with ROC-AUC 0.997–1.000.
4. **GenAI Brief & Evaluation Harness:** Azure OpenAI integration built with strict confidence-band hedging, zero-hallucination validation across 10 evaluation scenarios, and 100% deterministic template fallback.
5. **Replay Engine Ready:** Multi-scenario replay engine (`replay/replay.py`) streaming real traffic slices into batch ingest pipelines with live ground-truth metrics.

---

## 7. Expected Impact & Microsoft Innovate Alignment

- **Operational Efficiency:** Slashes alert fatigue by collapsing alert storms and ordering incident queues strictly by verified business risk.
- **Trust & Explainability:** Empowers Tier-1 analysts with exact feature deviations and natural-language briefings rather than opaque probability scores.
- **Honest, Responsible AI:** Operates with an explicit "Alert SOC, Never Auto-Block" philosophy, openly documents generalisation boundaries, and monitors real-world feature drift over time.

---

## 8. Formal References

1. **H. Holm**, *"Signature Based Intrusion Detection for Zero-Day Attacks: (Not) A Closed Chapter?"*, 47th Hawaii International Conference on System Sciences (HICSS), IEEE, 2014. [DOI: 10.1109/HICSS.2014.600](https://dl.acm.org/doi/10.1109/HICSS.2014.600).
2. **L. Liu, G. Engelen, T. Lynar, D. Essam, and W. Joosen**, *"Error-Prone Labeling and Flawed Evaluation in Network Intrusion Detection Datasets"*, IEEE Conference on Communications and Network Security (CNS), 2022.
3. **S. M. Raza, M. J. Won, and M. Choo**, *"LUFlow: An Extensive and Continuously Updated Honeypot Network Flow Dataset"*, Lancaster University, 2020.
4. **S. M. Lundberg and S.-I. Lee**, *"A Unified Approach to Interpreting Model Predictions"*, Advances in Neural Information Processing Systems (NeurIPS), 2017.
5. **Microsoft & Omdia**, *"State of the Security Operations Center (SOC) Report"*, Microsoft Security Publications, 2026.
