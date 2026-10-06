# NetSentinel Pitch Deck Specification

> **Event / Submission:** Microsoft Innovate 2026 — Round 2 Pitch
> **Problem Statement:** #26 — Catch the Attack the Signatures Miss
> **Team:** NetSentinel
> **Honesty Rule:** *No number goes in the deck unless the repository reproduces it.*
> **Deck Structure:** 12 Slides | Target Presentation Time: 4.5 – 5.0 Minutes

---

## Slide 1: Title & Core Value Proposition

### Visual Layout
- **Banner:** NetSentinel
- **Subtitle:** An Explainable ML Defense Layer That Prioritises What Signature IDS Misses
- **Tagline:** **Alert the SOC, Never Auto-Block.**
- **Badges:** Microsoft Innovate 2026 · Problem Statement #26 · Azure Machine Learning · Azure OpenAI

### Slide Body
- **The Core Promise:** Transforms high-volume, uncurated network flow alerts into grouped, explainable, risk-prioritised SOC incidents.
- **Enterprise Team:** 5 Cross-Functional Tracks (Data, ML, Backend, Console, GenAI).

### Presenter Notes (20s)
> *"Good morning. Signature-based intrusion detection systems miss over 80% of zero-day exploits, while flooding SOC analysts with thousands of false alarms every hour. We built NetSentinel: an explainable machine learning layer that flags what signatures miss, groups alerts into actionable incidents, and prioritises them by real-world consequence—without ever auto-blocking legitimate traffic."*

---

## Slide 2: The Problem — The SOC Alert Paradox

### Visual Layout
Two contrasting callout boxes:
```
┌──────────────────────────────────────┐     ┌──────────────────────────────────────┐
│       SIGNATURE IDS BLINDNESS        │     │          SOC ALERT FATIGUE           │
│                                      │     │                                      │
│                 83%                  │     │                 46%                  │
│     Zero-Day Attacks Missed by Snort │     │    Of All SOC Alerts Are False FPs   │
│         (Holm, HICSS 2014)           │     │       (Microsoft / Omdia 2026)       │
└──────────────────────────────────────┘     └──────────────────────────────────────┘
```

### Key Bullet Points
- **Signature Limitations:** Snort and Suricata only catch known attack fingerprints. Attackers modify packet timings, ports, and payloads to bypass regex rules.
- **Cognitive Exhaustion:** When machine learning is added naively, it sorts by raw probability ($P(\text{attack})$), pushing thousands of harmless port scans to the top.
- **The Operational Consequence:** High-risk internal intrusions get buried; critical compromises go unnoticed for months.

### Presenter Notes (25s)
> *"Every enterprise runs Snort or Suricata. Yet peer-reviewed research proves that Snort catches only 17% of zero-day attacks, missing 83%. Simultaneously, Microsoft and Omdia found that 46% of alerts hitting Tier-1 analysts are false alarms. Naive ML makes this worse by sorting by raw confidence—flooding queues with trivial port scans while active lateral compromises slip past."*

---

## Slide 3: Our Philosophy — Alert SOC, Never Auto-Block

### Visual Layout
- Flow diagram contrasting automated failure vs NetSentinel human-in-the-loop triage:
  ```
  Traditional SOAR / Auto-Block:
  Flow Flagged ──> Automated Firewall Drop ──> Self-Inflicted Outage! (Broken Production Service)

  NetSentinel Human-in-the-Loop:
  Flow Flagged ──> Correlate & Score Risk ──> Explain with SHAP ──> Actionable Brief ──> Analyst Decides
  ```

### Key Bullet Points
- **No Self-Inflicted Outages:** An automated block on a false positive takes down critical business infrastructure.
- **Decision-Ready Incidents:** Instead of raw packets, analysts receive an enriched card with risk breakdown, MITRE technique, SHAP feature context, and a recommended playbook step.
- **Measurable Feedback:** Analyst action buttons (*Acknowledge, Escalate, Confirm TP, Dismiss FP*) feed live analyst-confirmed precision metrics.

### Presenter Notes (20s)
> *"Our first design rule is: Alert the SOC, never auto-block. When a machine learning model misclassifies a database connection and auto-drops the firewall rule, that is a self-inflicted denial of service. NetSentinel keeps human experts in control by giving them decision-ready incidents they can triage in five seconds."*

---

## Slide 4: End-to-End Pipeline Architecture

### Visual Layout
```
[ Replay CSV / Flow Stream ]
            │
            ▼
[ FlowTransformer ] ──> Strips IPs, Ports, Timestamps (Zero Spatial Overfitting)
            │
            ├───> Stage 1: Random Forest Binary Head (p >= tau_binary)
            │
            └───> Stage 2: Random Forest Multi-Class Head (f_conf >= tau_family)
                                    │
                                    └───> Low Confidence ──> Verdict: NOVEL_ANOMALY
            │
            ▼
[ Incident Correlator ] ──> Groups by (src_ip, dst_ip, family) in 5-min window
            │
            ├───> [ TreeSHAP Explainer ] ──> Top-5 features vs Benign Medians (50 ms)
            │
            ├───> [ Risk Engine ]        ──> Confidence x Expected Severity x Burst
            │
            ▼
[ Streamlit SOC Console ] <── [ Azure OpenAI Brief Service ] (gpt-4o-mini / Template)
```

### Key Bullet Points
- **Contract-First Monorepo (`nscore/`):** Feature transforms, risk math, and contracts are shared between training and serving, preventing train/serve skew by construction.
- **Spec-Driven:** Adapts cleanly to both CIC and LUFlow feature schemas without custom branches.

### Presenter Notes (25s)
> *"Here is how NetSentinel works: Network flows are transformed using strict feature specs that drop all IP and port identifiers to prevent spatial leakage. A dual-head Random Forest detects attacks and classifies known families. Unfamiliar attacks are flagged as novel anomalies. The correlator groups flows into incidents, our risk engine computes urgency, and fast TreeSHAP explains why."*

---

## Slide 5: Two Datasets for Two Distinct Jobs

### Visual Layout
```
┌──────────────────────────────────────────────┐  ┌──────────────────────────────────────────────┐
│        CSE-CIC-IDS2018 (CORRECTED)           │  │               LUFLOW HONEYPOTS               │
│                                              │  │                                              │
│  Job: Train, Validate, Test & LOAO           │  │  Job: Real-World Showcase & Live Drift       │
│  Scope: 45.2M clean flows (10 capture days)  │  │  Scope: 44.9M clean flows (2020 - 2021)      │
│  Network: 420 AWS hosts, 30 enterprise servers│ │  Network: Real Lancaster University internet │
│  Audit: Liu & Engelen (IEEE CNS 2022) bugs   │  │  Telemetry: Unscripted internet background   │
│         resolved; audited multi-class labels │  │  Features: Real temporal drift + outliers    │
└──────────────────────────────────────────────┘  └──────────────────────────────────────────────┘
```

### Key Bullet Points
- **Why Not Single Lab Data?** Academic IDS papers overclaim because they test on closed, scripted labs. We deploy against both an audited enterprise network and real-world internet honeypots.
- **Audited Integrity:** Original 2018 files had corrupt labels and missing IPs; we use the corrected release.

### Presenter Notes (25s)
> *"We do not rely on a single lab dataset. We use two datasets for two specific jobs. First, the corrected CSE-CIC-IDS2018 benchmark by Liu and Engelen: 45 million clean flows across 420 enterprise machines with audited attack labels. Second, Lancaster University's LUFlow: 44.9 million clean flows of authentic, unscripted internet honeypot traffic collected across multiple months to evaluate real-world performance."*

---

## Slide 6: Risk Scoring — Consequence vs. Certainty

### Visual Layout
- **The Formula:**
  $$\text{Risk Score } = \text{round}\left(100 \times \left(\text{Confidence} \times \text{Expected Severity} \times \text{Burst Factor} + \text{Novelty Bonus}\right)\right)$$
- **Severity Lookup Table ($W$):**
  - Infiltration: `1.00` (Attacker already inside internal subnet)
  - Botnet C2: `0.90` (Active endpoint host compromise)
  - DDoS / DoS: `0.80` (Mission-critical service disruption)
  - Brute Force: `0.70` (Attempted credential access)
  - Web Attack: `0.60` (External exploit attempt, frequently blocked by WAF)
  - Port Scan: `0.30` (Perimeter reconnaissance only)
- **Burst Multiplier:** $1.00$ for 1 flow $\to$ smoothly scales to $1.15$ for $\ge 1,000$ flows.

### Worked Examples (Directly Verified in Fixtures & Tests)
- **External Port Scan:** $0.95 \text{ (sure)} \times 0.30 \text{ (low danger)} \times 1.00 = \mathbf{28 \text{ (LOW)}}$
- **Internal Infiltration:** $0.81 \text{ (less sure)} \times 1.00 \text{ (critical breach)} \times 1.00 = \mathbf{81 \text{ (HIGH)}}$
- **DDoS Storm (4,210 flows):** $0.99 \times 0.80 \times 1.15 = \mathbf{91 \text{ (HIGH)}}$

### Presenter Notes (30s)
> *"Why not just rank by model probability? Because confidence measures certainty, but severity measures consequence. A model can be 95% certain about an external port scan, but port scanning is just reconnaissance—it carries a severity of 0.3, scoring a LOW 28. Conversely, internal lateral infiltration carries a severity of 1.0; even at 81% confidence, it scores 81 HIGH. Our continuous burst factor scales sustained storms up to 1.15, guaranteeing that high-volume floods jump to the top."*

---

## Slide 7: Explainability — Why SHAP Never Changes the Score

### Visual Layout
- **Mockup of Incident Detail Card:**
  - Risk Badge: `HIGH (Score: 81)`
  - Primary Drivers (Top-5 TreeSHAP vs Benign Medians):
    * `flow_duration`: 35 µs *(1,767× shorter than median 61,844 µs)*
    * `flow_iat_mean`: 12 µs *(4,017× shorter than median 48,210 µs)*
    * `syn_flag_count`: 1.0 *(Elevated vs normal 0)*

### Key Bullet Points
- **Fast TreeSHAP (~50–110 ms):** Approximates local attribution over 25 trees for line-rate execution.
- **The Decoupling Rule:** SHAP explains *why* the flow was flagged, but **never alters the risk score**.
- **Why?** Factoring SHAP into the score creates non-deterministic feedback loops, double-counts statistical variance already in the confidence probability, and invites adversarial feature manipulation.

### Presenter Notes (25s)
> *"Explainability builds trust, but one number must decide priority. NetSentinel computes exact TreeSHAP attributions in 50 milliseconds, comparing flow features directly against empirical benign medians. An analyst sees immediately that packet inter-arrival times are 4,000 times shorter than normal. Crucially, SHAP never alters the risk score—one number decides the queue, one explanation builds trust."*

---

## Slide 8: Catching Unseen Attacks — Leave-One-Attack-Out (LOAO)

### Visual Layout
Grouped bar chart / table summarizing LOAO results ([docs/experiments.md](experiments.md)):
```
+--------------------+-----------------------+---------------------+
| Attack Family Held | Recall When Seen      | Recall When UNSEEN  |
| Out of Training    | (Trained WITH Family) | (Never Trained On)  |
+--------------------+-----------------------+---------------------+
| DDoS Floods        | 100.0%                | 99.8%  [99.8-99.9]  |
| Endpoint DoS       | 99.9%                 | 99.1%  [99.0-99.2]  |
| Ares Botnet C2     | 100.0%                | 66.0%  [64.0-68.0]* |
| SSH Brute Force    | 100.0%                | 97.0%  (at 0.1% FPR)|
| Internal Nmap Scan | 99.2%                 |  1.0%  (Missed)     |
+--------------------+-----------------------+---------------------+
*Note: Ares Botnet reaches 99.0% recall at 0.5% FPR budget.
```

### Key Bullet Points
- **Unfamiliar Signal:** The family head's confidence separates unfamiliar from familiar attacks with **ROC-AUC 0.997–1.000**.
- **Honest Generalisation:** The supervised forest generalises on behavioral volume (DDoS, DoS, Botnet), but misses slow internal port sweeps when unseen.

### Presenter Notes (25s)
> *"Judges ask: 'If it's supervised, how do you catch an attack you've never seen?' We proved it with Leave-One-Attack-Out experiments. We retrained the model without DDoS, and it still caught 99.8% of flood flows. We retrained without Botnet, and caught 66% at strict budgets and 99% at 0.5% FPR. The binary forest recognises the malicious anomaly, and the family head flags it as an unfamiliar novel variant."*

---

## Slide 9: Real-World Traffic & Measured Drift (LUFlow)

### Visual Layout
- **Temporal Drift Curve:** Monthly feature PSI across 7 test months:
  ```
  PSI Level
   0.40 ──                                 [0.39 July]             [0.36 Dec]
   0.25 ── ALERT THRESHOLD ──────────────────────────────────────────────────────────
   0.18 ──                                             [0.18 Nov]
   0.10 ── WATCH THRESHOLD ──────── [0.10 Oct] ────────────────────────── [0.10 Feb]
   0.00 ──
  ```
- **Demo Recovery Path:** Reloading `netsentinel-luflow-recal` in the replay scenario demonstrates the intended drift-recovery workflow.

### Key Bullet Points
- **Measured on Live Telemetry:** Max feature PSI crossed the 0.25 alert line in July (0.39) and December (0.36) 2020.
- **Label-Free Recalibration:** Demonstrates that models can be recalibrated on a recent window of benign traffic without expensive manual labeling.

### Presenter Notes (25s)
> *"Model drift is an explicit competition requirement. On LUFlow honeypots, we measured authentic temporal drift: feature PSI crossed our 0.25 alert threshold in July and December. Our system flashes a drift alert, operators trigger label-free recalibration on recent benign traffic, and monitoring returns to normal. We don't just discuss drift—we measure it and recover from it."*

---

## Slide 10: Grounded GenAI Incident Briefs

### Visual Layout
- **Comparison Box:**
  ```
  Unconstrained GenAI:
  "Possible APT29 attack exploiting CVE-2024-1234 on domain controller..." (HALLUCINATION!)

  NetSentinel Grounded Brief (Azure OpenAI + Template Fallback):
  "Active SSH-BruteForce activity detected from 18.221.219.4 to 172.31.69.25:22 across 10,000 flows.
  Flow duration is 12x shorter than typical baseline.
  Immediate action required: Enforce IP rate-limiting and temporary account lockout on target service."
  ```

### Key Bullet Points
- **Azure OpenAI Integration:** Calls `gpt-4o-mini` with structured JSON inputs (no raw payloads).
- **Strict Guardrails:** Hedging matches confidence bands; novel anomalies state *no known family matched*; malicious flows do not invent an attack type.
- **8-Second SLA & Template Fallback:** If Azure OpenAI times out or errors, deterministic template brief renders instantly. 10/10 evaluation scenarios passed.

### Presenter Notes (25s)
> *"SOC analysts don't have time to read raw logs. NetSentinel drafts a grounded 3-sentence briefing using Azure OpenAI. We enforce strict guardrails: the model can only use structured flow fields, its tone must hedge to the confidence score, and it can never invent CVEs. To guarantee reliability, if Azure OpenAI takes more than 8 seconds, our deterministic template fallback steps in instantly."*

---

## Slide 11: Honest Limitations & Engineering Ethics

### Visual Layout
Three clear limitation callouts:
```
┌─────────────────────────────┐ ┌─────────────────────────────┐ ┌─────────────────────────────┐
│     LAB BOUNDARIES (2018)   │ │    OPERATING FPR BUDGET     │ │      FLOW METADATA ONLY     │
│                             │ │                             │ │                             │
│ While 2018 is audited and   │ │ 0.1% benign FPR generates   │ │ No deep packet payload      │
│ large, attacks are scripted.│ │ hundreds of flows/hr.       │ │ inspection or TLS           │
│ LUFlow provides real check. │ │ Incident grouping is vital. │ │ decryption. Never auto-block│
└─────────────────────────────┘ └─────────────────────────────┘ └─────────────────────────────┘
```

### Key Bullet Points
- **Unseen Scan Limits:** LOAO showed that unseen internal Nmap scans and LOIC-HTTP tools are missed at strict budgets; we do not claim universal zero-day detection.
- **WebAttack Low Support:** WebAttack has only 283 flows in 2018; metrics have wide confidence intervals.
- **Operating Curves:** We report full operating curves (0.01%–1.0% FPR) so operators select thresholds based on real network scale.

### Presenter Notes (20s)
> *"We believe in honest cybersecurity engineering. We do not claim perfect zero-day detection: our benchmark proves that slow Nmap scans are missed when held out entirely from training. We openly report that 0.1% false-alarm rates still require our incident correlator to manage volume. Real security requires transparency, not inflated accuracy claims."*

---

## Slide 12: Summary & Microsoft Ecosystem Alignment

### Visual Layout
- **NetSentinel Architecture Summary Card:**
  - **Shared Core:** `nscore/` contract-first shared library
  - **Model Registry:** Azure Machine Learning SDK v2 with SHA256 verification
  - **GenAI Summaries:** Azure OpenAI (`gpt-4o-mini`)
  - **Serving API:** FastAPI with WAL SQLite
  - **Console:** Interactive Streamlit SOC Dashboard
- **Headline Achievement:**
  $$\mathbf{45.2\text{M Clean Flows}} \quad \vert \quad \mathbf{0.1\% \text{ FPR Budget}} \quad \vert \quad \mathbf{10,000\text{ Flows} \to 1\text{ Correlated Incident}} \quad \vert \quad \mathbf{\text{Zero Auto-Blocks}}$$

### Presenter Notes (20s)
> *"NetSentinel bridges the gap between machine learning research and frontline SOC operations. Built natively on Microsoft Azure ML and Azure OpenAI, it delivers transparent, risk-prioritised incidents that empower human analysts to catch the attacks signatures miss. Thank you, and we welcome your questions."*
