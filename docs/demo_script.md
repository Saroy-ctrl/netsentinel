# NetSentinel Live Demo Script

> **Track & Task:** M5-06 Demo Design
> **Target Run Time:** ~5 minutes
> **Demo Storyline Base:** [docs/03_architecture.md §6](03_architecture.md#6-demo-storyline--5-min)
> **Replay Engine:** `replay/replay.py` via `replay/scenarios/*.yaml`
> **Core Narrative:** How NetSentinel turns a raw, high-volume firehose of network flows into explainable, prioritised SOC incidents, handles novel attacks, detects real-world distribution drift, and **never auto-blocks**.

---

## 1. Preflight Checklist & Environment Setup

Run this preflight sequence **10 minutes before the presentation**.

```bash
# 1. Activate environment and verify working directory
cd /path/to/netsentinel

# 2. Check contract and test health
python -m pytest tests/test_contracts.py tests/test_contract_artifacts.py api/tests/test_brief.py tests/test_replay.py

# 3. Ensure replay samples and scenarios are present
python -c "import pathlib; assert (pathlib.Path('replay/samples/manifest.json')).exists()"

# 4. Mode Selection:
# Option A (Live Integration - I2 Milestone):
#   - Start API: uvicorn api.app.main:app --port 8000
#   - Start Dashboard: streamlit run dashboard/app.py
# Option B (Mock / Standalone Demo - Ready Now):
#   - Replay runs with `--mock` flag (in-process contract scoring)
#   - Dashboard runs in offline fixture mode (`NS_OFFLINE=1`)
```

### Safety & Grounding Rules
- **No external targets:** All traffic is replayed from audited offline slices (`replay/samples/`).
- **No network scanning:** Replay connects strictly to `localhost:8000` or executes in `--mock` mode.
- **No live API keys in presentations:** Environment variables load from `.env`.

---

## 2. Demo Timing & Scene Overview

| Act | Scenario / File | Target Time | Headline Concept Shown |
|:---:|---|:---:|---|
| **Pre** | Architecture Overview | 0:00 – 0:30 | The problem: alert fatigue & signature blindness |
| **Act 1** | `act1_calm` (`2018_benign_background`) | 0:30 – 1:15 | Baseline health, calm queue, zero false positives |
| **Act 2** | `act2_bruteforce` (`2018_ssh_bruteforce`) | 1:15 – 2:15 | Known attack burst $\to$ 1 incident, risk breakdown, GenAI brief |
| **Act 3** | `act3_ddos` (`2018_ddos_hoic`) | 2:15 – 3:00 | Alert storm collapse: 10,000 flows $\to$ 1 HIGH incident |
| **Act 4** | `act4_botnet_holdout` (`2018_botnet_ares`) | 3:00 – 4:00 | Novel attack detection via holdout bundle $\to$ `novel_anomaly` |
| **Act 5** | `act5_luflow_drift` (`luflow_2021-02`) | 4:00 – 4:45 | Real internet traffic, drift alert (PSI $\ge 0.25$), recovery |
| **Wrap** | Honest Limitations & Q&A | 4:45 – 5:00+ | "Alert SOC, Never Auto-Block" philosophy |

---

## 3. Act-by-Act Execution Walkthrough

---

### Act 1: The Calm Baseline (0:30 – 1:15)

**Objective:** Prove that benign business traffic does not generate noise or trigger alert fatigue.

#### Exact Command
```bash
python replay/replay.py --scenario act1_calm --speed 5.0 --mock
```
*(When M3 live API is running, omit `--mock`: `python replay/replay.py --scenario act1_calm --speed 5.0`)*

#### Expected Console Output
```text
================================================================================
NETSENTINEL REPLAY: act1_calm
File: replay/samples/2018_benign_background.csv.gz | Bundle: netsentinel-bundle | Flows: 10,000
Speed: 5.0x | Batch size: 250 | Mode: Mock
================================================================================

[  1/40] Sent    250/10,000 flows (  2.5%) | Detections: 0 Known, 0 Novel, 250 Benign | Precision: 100.0% | Recall: 100.0%
...
[ 40/40] Sent 10,000/10,000 flows (100.0%) | Detections: 0 Known, 0 Novel, 10,000 Benign | Precision: 100.0% | Recall: 100.0%

--------------------------------------------------------------------------------
REPLAY SUMMARY: act1_calm
Flows Replayed : 10,000 in ~14.2s (704 flows/s)
Detections     : 0 Known | 0 Novel | 10,000 Benign
Incidents      : 0 Created, 0 Updated
Precision      : 100.00% | Recall: 100.00% | F1: 1.0000
Ground Truth   : {'BENIGN': 10000}
--------------------------------------------------------------------------------
```

#### What the Presenter Says
> *"We start with normal enterprise traffic on an AWS network of 420 hosts. Notice that NetSentinel ingests thousands of flows per second, yet the SOC queue remains completely empty. Drift is green, the false-alarm rate is calibrated to zero, and the Tier-1 analyst is not being inundated with background noise."*

#### What the Audience Notices
- Queue is empty (0 incidents created).
- Benign throughput is smooth and high-speed.

---

### Act 2: The Known Attack Burst (1:15 – 2:15)

**Objective:** Show detection of an active attack, grouping into one incident, mathematical risk breakdown, and grounded GenAI briefing.

#### Exact Command
```bash
python replay/replay.py --scenario act2_bruteforce --speed 2.0 --mock
```

#### Expected Console Output
```text
================================================================================
NETSENTINEL REPLAY: act2_bruteforce
File: replay/samples/2018_ssh_bruteforce.csv.gz | Bundle: netsentinel-bundle | Flows: 10,000
Speed: 2.0x | Batch size: 250 | Mode: Mock
================================================================================

[  1/40] Sent    250/10,000 flows (  2.5%) | Detections: 250 Known, 0 Novel, 0 Benign | Precision: 100.0% | Recall: 100.0%
...
[ 40/40] Sent 10,000/10,000 flows (100.0%) | Detections: 10,000 Known, 0 Novel, 0 Benign | Precision: 100.0% | Recall: 100.0%

--------------------------------------------------------------------------------
REPLAY SUMMARY: act2_bruteforce
Detections     : 10,000 Known | 0 Novel | 0 Benign
Incidents      : 1 Created, 9,999 Updated
Precision      : 100.00% | Recall: 100.00% | F1: 1.0000
Ground Truth   : {'BruteForce': 10000}
--------------------------------------------------------------------------------
```

#### Expected Dashboard Screen (Incident Detail)
- **Incident Badge:** `INC-1004` | `BruteForce` | `MEDIUM (Score: 62)` | MITRE `T1110: Brute Force`.
- **Mathematical Risk Breakdown:**
  $$\text{Risk Score } 62 = \text{Confidence } (0.88) \times \text{Severity } (0.70) \times \text{Burst } (1.00)$$
- **SHAP Bar Chart:** Shows `flow_duration` and `total_fwd_packets` deviating significantly from benign median.
- **Incident Brief Panel:**
  > *"Active BruteForce (MITRE T1110) activity detected from 18.221.219.4 to 172.31.69.25:22 across 10,000 flows. The traffic matches BruteForce behavioral patterns: flow duration is ~12x shorter than typical. Immediate action required: Enforce IP rate-limiting and temporary account lockout on the target authentication service (SSH/FTP), and review auth logs for unauthorized logins."*

#### What the Presenter Says
> *"An adversary launches an automated SSH brute force campaign. Ten thousand login attempts hit our server. Instead of 10,000 alerts, NetSentinel groups them into exactly ONE incident. Look at the risk breakdown: the model is 88% confident, but credential guessing carries a severity of 0.70—an attempted breach, not a confirmed compromise. That places it at Medium risk. We click 'Generate Brief' and receive a grounded, 3-sentence summary with the exact MITRE technique and playbook action. The analyst acknowledges and escalates in seconds."*

---

### Act 3: The Alert Storm (2:15 – 3:00)

**Objective:** Prove that volumetric DDoS attacks collapse into a single actionable incident, solving alert fatigue.

#### Exact Command
```bash
python replay/replay.py --scenario act3_ddos --speed 1.0 --mock
```

#### Expected Console Output
```text
================================================================================
NETSENTINEL REPLAY: act3_ddos
File: replay/samples/2018_ddos_hoic.csv.gz | Bundle: netsentinel-bundle | Flows: 10,000
Speed: 1.0x | Batch size: 500 | Mode: Mock
================================================================================

[  1/20] Sent    500/10,000 flows (  5.0%) | Detections: 500 Known, 0 Novel, 0 Benign | Precision: 100.0% | Recall: 100.0%
...
[ 20/20] Sent 10,000/10,000 flows (100.0%) | Detections: 10,000 Known, 0 Novel, 0 Benign | Precision: 100.0% | Recall: 100.0%

--------------------------------------------------------------------------------
REPLAY SUMMARY: act3_ddos
Incidents      : 1 Created, 9,999 Updated
Detections     : 10,000 Known | 0 Novel | 0 Benign
Precision      : 100.00% | Recall: 100.00% | F1: 1.0000
Ground Truth   : {'DDoS': 10000}
--------------------------------------------------------------------------------
```

#### What the Presenter Says
> *"Now the attacker pivots to a high-rate DDoS flood using the HOIC tool. Thousands of packets hammer the gateway. In a traditional IDS, the analyst's screen scrolls endlessly. Here, the correlator absorbs the entire storm into a single HIGH incident. Because of the volume, the continuous burst factor scales to its maximum 1.15 multiplier, pushing the risk score to 91. That is our answer to alert fatigue."*

---

### Act 4: The Novel Attack (3:00 – 4:00)

**Objective:** The headline technical achievement. Demonstrate how NetSentinel catches an attack family it was **never trained on**.

#### 1. Bundle Reload
*Live API Command:*
```bash
curl -X POST http://localhost:8000/v1/admin/reload-model \
  -H "X-Admin-Key: change-me-too" \
  -d '{"model_ref": "netsentinel-demo-holdout-botnet"}'
```
*(In mock/standalone replay, pass `--bundle netsentinel-demo-holdout-botnet` directly)*

#### 2. Replay Ares Botnet Traffic
```bash
python replay/replay.py --scenario act4_botnet_holdout --speed 2.0 --mock
```

#### Expected Console Output
```text
================================================================================
NETSENTINEL REPLAY: act4_botnet_holdout
File: replay/samples/2018_botnet_ares.csv.gz | Bundle: netsentinel-demo-holdout-botnet | Flows: 10,000
Speed: 2.0x | Batch size: 250 | Mode: Mock
================================================================================

[  1/40] Sent    250/10,000 flows (  2.5%) | Detections: 0 Known, 250 Novel, 0 Benign | Precision: 100.0% | Recall: 100.0%
...
[ 40/40] Sent 10,000/10,000 flows (100.0%) | Detections: 0 Known, 10,000 Novel, 0 Benign | Precision: 100.0% | Recall: 100.0%

--------------------------------------------------------------------------------
REPLAY SUMMARY: act4_botnet_holdout
Detections     : 0 Known | 10,000 Novel | 0 Benign
Incidents      : 1 Created, 9,999 Updated
Precision      : 100.00% | Recall: 100.00% | F1: 1.0000
Ground Truth   : {'Botnet': 10000}
--------------------------------------------------------------------------------
```

#### Expected Dashboard Screen
- **Incident Badge:** `INC-1002` | `Novel anomaly` | `Attack Family: Unknown` | `Closest: DDoS (55% heuristic)`.
- **Brief Text:**
  > *"Possible novel activity from 18.219.211.138 to 172.31.69.25:8080 across 10,000 flows. No known attack family matched, but the traffic sits far outside normal behaviour: flow inter-arrival times are ~4,000x shorter than typical. Recommended action: Review top SHAP feature deviations against normal traffic baselines, capture PCAP for deep packet inspection, and verify whether the flow represents an unmodeled protocol or zero-day behavior."*

#### What the Presenter Says
> *"Here is the critical question judges always ask: 'You're using supervised Random Forests—how can you catch an attack you've never seen?' Watch this. We reloaded a model trained without any botnet data. It has literally never seen Ares traffic. The binary forest detects the attack behavior, but our multi-class family head is unsure. NetSentinel does not drop the alert—it flags it as a NOVEL ANOMALY. It tells the analyst: 'No known family matched, but this sits far outside normal baselines.' We back this with our Leave-One-Attack-Out benchmark across all families."*

---

### Act 5: Real Traffic, Live Drift & Recalibration (4:00 – 4:45)

**Objective:** Move beyond lab data to real-world internet honeypots (LUFlow), demonstrate temporal drift detection, and show label-free recovery.

#### 1. Switch to LUFlow Bundle
```bash
curl -X POST http://localhost:8000/v1/admin/reload-model \
  -H "X-Admin-Key: change-me-too" \
  -d '{"model_ref": "netsentinel-luflow"}'
```

#### 2. Replay February 2021 Honeypot Traffic
```bash
python replay/replay.py --scenario act5_luflow_drift --speed 10.0 --mock
```

#### Expected Console & Drift State
- Replay processes 10,000 flows from February 2021 (7 months after training baseline).
- The Drift Monitor observes feature distributions over the rolling 2,000-flow window.
- **Drift Snapshot on Dashboard (`/v1/drift`):**
  - Status changes from `OK` $\to$ **`ALERT`** (Red banner).
  - Max Feature PSI: **`0.36`** (above the 0.25 alert reference line).
  - Banner: *"Input distribution has drifted significantly (PSI = 0.36). Consider recalibrating."*

#### 3. Reload Recalibrated Bundle (`netsentinel-luflow-recal`)
```bash
curl -X POST http://localhost:8000/v1/admin/reload-model \
  -H "X-Admin-Key: change-me-too" \
  -d '{"model_ref": "netsentinel-luflow-recal"}'
```
- Re-run replay slice: PSI drops back below 0.10 $\to$ Status **`OK`** (Green).

#### What the Presenter Says
> *"Anyone can show high accuracy on a closed lab dataset. We went further: we deployed NetSentinel against LUFlow—real, unscripted internet honeypot traffic collected at Lancaster University across multiple months. Watch what happens when we replay traffic from February 2021 against a July 2020 model: the internet drifted. Our PSI monitor flashes an ALERT because feature distributions shifted. We reload our recalibrated bundle—refit on a recent benign window with zero manual labels required—and the drift monitor recovers to OK."*

---

### Wrap-Up & Honesty (4:45 – 5:00)

**Objective:** Reinforce responsible AI and defensible cybersecurity engineering.

#### What the Presenter Says
> *"To conclude: NetSentinel does not promise zero false positives or magical zero-day detection. We openly publish our Leave-One-Attack-Out limits in our model card. But by combining dual-head detection, incident grouping, consequence-driven risk math, fast TreeSHAP explanations, and grounded GenAI briefs, we give Tier-1 analysts what they actually need: an alert queue they can trust, where the most dangerous threat is always at the top."*

---

## 4. Failure Modes & Emergency Fallback Procedures

| What Breaks | Symptom During Demo | Immediate 5-Second Recovery Action |
|---|---|---|
| **FastAPI Backend Down / Crash** | Connection refused on `http://localhost:8000` | Run replay commands with `--mock`. Replay prints complete metrics in-process using contract schemas. |
| **Azure OpenAI Latency / Outage** | Brief spinner hangs | The brief service enforces a strict **8.0-second timeout** and automatically renders the deterministic template brief (`source: "template"`). Point out: *"Our 8-second SLA timed out, so our template fallback provided the brief without blocking the queue."* |
| **Streamlit UI Fails to Render** | Browser error / session disconnect | Open `http://localhost:8000/docs` (Swagger UI) or demonstrate via console replay metrics. |
| **Total Machine / Network Outage** | Complete local failure | Play the pre-recorded fallback video (`docs/pdf/` / demo backup MP4) covering Acts 1–5. |

---

## 5. Architectural Implementation Status

| Feature / Artifact | Current Status | Supporting Module / Task |
|---|:---:|---|
| **Scenario YAMLs (Acts 1–5)** | **Implemented & Tested** | `replay/scenarios/*.yaml` |
| **Replay Engine CLI & Mock Mode** | **Implemented & Tested** | `replay/replay.py` (M5-05) |
| **Grounded Briefs & Template Fallback**| **Implemented & Tested** | `api/app/services/brief.py` (M5-03) |
| **10-Incident Brief Evaluation** | **Evaluated & Verified** | `api/app/services/brief_eval.py` (M5-04) |
| **Risk Scoring & MITRE Mapping** | **Implemented & Tested** | `nscore/contracts/policy.py` (M5-01) |
| **FastAPI `/v1/flows` Ingest Endpoint**| Blocked on Track M3 | Task M3-04 (M3 Backend Track) |
| **Streamlit Interactive UI** | Blocked on Track M4 | Task M4-03 / M4-04 (M4 Console Track) |
| **Live Azure ML Model Pull** | Tested with Fake Client | Task M2-12 / Azure Subscription required |
