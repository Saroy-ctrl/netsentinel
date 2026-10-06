# NetSentinel Live Demo Script

> **Track & Task:** M5-06 Demo Design
> **Target Run Time:** ~5 minutes
> **Demo Storyline Base:** [docs/03_architecture.md §6](03_architecture.md#6-demo-storyline--5-min)
> **Replay Engine:** `replay/replay.py` via `replay/scenarios/*.yaml`
> **Core Narrative:** How NetSentinel turns a raw, high-volume firehose of network flows into explainable, prioritised SOC incidents, handles novel attacks, detects real-world distribution drift, and **never auto-blocks**.

**Every output below was produced by a live run** (API + real model bundles + replay, 2026-10-06). Numbers you show must come from
the screen, never from this page or from `--mock`.

---

## 1. Preflight Checklist & Environment Setup

Run this **10 minutes before the presentation** (PowerShell, from the repo root). The real bundles live in `artifacts/bundles/`
(`cic-v1`, `cic-holdout-botnet`, `luflow-v1`); they are not in git, so copy them onto the demo laptop beforehand.

```powershell
# 1. Health
python -m pytest -q                                     # everything must pass
python scripts/init_db.py                               # fresh database for the demo

# 2. API (terminal 1). Use 127.0.0.1, NOT localhost: on Windows "localhost" adds ~2 s to every request.
$env:MODEL_REF = "local:artifacts/bundles/cic-v1"; $env:NS_DB_PATH = "netsentinel.db"
$env:NS_API_KEY = "<demo-key>"; $env:NS_ADMIN_KEY = "<demo-admin-key>"
uvicorn api.app.main:app --host 127.0.0.1 --port 8000

# 3. Dashboard (terminal 2)
$env:NS_API_URL = "http://127.0.0.1:8000"
streamlit run dashboard/app.py                          # http://localhost:8501

# 4. Replay (terminal 3): same keys as the API. With NS_ADMIN_KEY set, replay switches the API to each act's model itself.
$env:NS_API_URL = "http://127.0.0.1:8000"; $env:NS_API_KEY = "<demo-key>"; $env:NS_ADMIN_KEY = "<demo-admin-key>"
```

Optional: set `AZURE_OPENAI_ENDPOINT` / `AZURE_OPENAI_API_KEY` / `AZURE_OPENAI_DEPLOYMENT` for Azure OpenAI briefs. Without them
the briefs come from the deterministic template (`source: template`), which is what the outputs below show.

### Safety & Grounding Rules
- **No external targets:** all traffic is replayed from audited offline slices (`replay/samples/`).
- **No network scanning:** replay only talks to the local API.
- **No fabricated results:** if the API fails, replay stops with an error. `--mock` exists for development only; it copies the
  ground-truth labels into the verdicts and prints `SIMULATED` on every run. **Never show `--mock` output as results.**
- **No live API keys in presentations:** keys come from environment variables, never from slides or the screen.

---

## 2. Demo Timing & Scene Overview

Replay times: full 10,000-flow runs measured at the scenario speeds; with `--max-flows 3000` scaled from those runs.

| Act | Command | Replay time | Headline concept shown |
|:---:|---|:---:|---|
| **Pre** | Architecture overview | 0:30 | The problem: alert fatigue & signature blindness |
| **Act 1** | `act1_calm` | ~23 s | Baseline: 10,000 benign flows, 14 false alarms (0.14%) |
| **Act 2** | `act2_bruteforce -n 3000` | ~27 s | 3,000 SSH attempts -> **1 incident**, risk breakdown, brief |
| **Act 3** | `act3_ddos` | ~46 s | Alert storm: 10,000 DDoS flows -> 20 incidents (one per attacking host) |
| **Act 4** | `act4_botnet_holdout -n 3000` | ~28 s | Model never trained on botnets -> **novel_anomaly** |
| **Act 5** | `act5_luflow_drift -n 3000` | ~30 s | Real internet traffic, drift ALERT, outlier capture |
| **Wrap** | Honest limitations & Q&A | 0:15+ | "Alert SOC, never auto-block" |

---

## 3. Act-by-Act Execution Walkthrough

---

### Act 1: The Calm Baseline

**Objective:** Show that normal traffic produces very little noise.

```powershell
python replay/replay.py --scenario act1_calm
```

#### Real console output (summary)
```text
Mode: LIVE http://127.0.0.1:8000
Model: cic-v1-20261002
Flows Replayed : 10,000 in 22.57s (443 flows/s)
Detections     : 3 Known | 11 Novel | 9,986 Benign
Incidents      : 10 Created, 4 Updated
Precision      : n/a (no attack flows in this replay)
False alarms   : 14 of 10,000 benign flows (0.14%)
```

#### Dashboard
- Queue: 10 incidents, **0 HIGH**, 2 MEDIUM, 8 LOW. The top one is a single-flow `Infiltration` guess at risk 46 MEDIUM
  (confidence 0.46): exactly the kind of low-confidence alert an analyst dismisses with "Dismiss as FP".
- Drift: about **0.30 on timing features** (`flow_iat_std`, `flow_duration`). This replay is one 72-second slice of one busy day, so
  its timing differs from the 10-day training average. Say so if asked; do not claim the monitor is green.

#### What the Presenter Says
> *"We start with normal traffic on a 420-host network. Ten thousand flows go through, and the model raises fourteen alerts,
> 0.14%, all low-confidence and ranked at the bottom of the queue. That is the false-alarm budget we calibrated for: 0.1% on
> validation. Alerts are grouped into incidents, so the analyst sees ten small items, not fourteen pop-ups."*

---

### Act 2: The Known Attack Burst

**Objective:** Detection, grouping into one incident, the risk breakdown and the brief.

```powershell
python replay/replay.py --scenario act2_bruteforce --max-flows 3000
```

#### Real console output (full 10,000-flow run)
```text
Model: cic-v1-20261002
Detections     : 10,000 Known | 0 Novel | 0 Benign
Incidents      : 1 Created, 9,999 Updated
Precision      : 100.00% | Recall: 100.00% | F1: 1.0000
```

#### Dashboard (Incident Detail)
- `known_attack` | `BruteForce` | **HIGH, risk 80** | MITRE `T1110` | 13.58.98.64 -> 172.31.69.25:22.
- **Risk breakdown:** confidence 1.00 x severity 0.70 x burst 1.15 = 0.805 -> **80**.
- **Why (SHAP, value vs benign median):** `fwd_seg_size_min` 32 vs 20, `fwd_init_win_bytes` 26,883 vs 8,192, `bwd_init_win_bytes` 230 vs 141.
- **Brief (template):** *"Active BruteForce (MITRE T1110) activity detected from 13.58.98.64 to 172.31.69.25:22 across 10,000 flows.
  The traffic matches BruteForce behavioral patterns: fwd seg size min is 32.0 vs baseline 20.0 and fwd init win bytes is ~3x higher
  than typical. Immediate action required: Enforce IP rate-limiting and temporary account lockout on the target authentication
  service (SSH/FTP), and review auth logs for unauthorized logins."*

#### What the Presenter Says
> *"An attacker starts an automated SSH brute force. Thousands of login attempts, and NetSentinel shows exactly ONE incident.
> The risk breakdown is on screen: the model is certain, credential guessing has severity 0.7, the burst pushes it to 80, HIGH.
> The explanation shows which connection properties differ from normal traffic, and the brief gives the MITRE technique and a
> next step. The analyst acknowledges or escalates; nothing is blocked automatically."*

---

### Act 3: The Alert Storm

**Objective:** A volumetric attack collapses into a handful of actionable incidents.

```powershell
python replay/replay.py --scenario act3_ddos
```

#### Real console output
```text
Model: cic-v1-20261002
Flows Replayed : 10,000 in 45.70s (219 flows/s)
Detections     : 8,797 Known | 1,203 Novel | 0 Benign
Incidents      : 20 Created, 9,980 Updated
Precision      : 100.00% | Recall: 100.00% | F1: 1.0000
```

#### Dashboard
- **20 incidents, all HIGH**: one per attacking host (the correlator groups by source, destination and family).
- About 12% of the flows were flagged as *unfamiliar* variants (`novel_anomaly`): the binary model was certain they are attacks,
  the family model was not sure which family. Those incidents sit at the top, risk 98-99, because the risk engine adds a novelty
  bonus. Top example: 18.216.200.189 -> 172.31.69.28:80, 164 flows, risk 99 = 1.00 x 0.80 x 1.11 + 0.10 novelty.

#### What the Presenter Says
> *"Now a DDoS with the HOIC tool: ten thousand flows from many machines. A signature IDS fires ten thousand alerts; here the analyst
> gets twenty, one per attacking host, all HIGH. Notice some are marked 'unfamiliar': the model is sure they are attacks but they
> don't look exactly like the DDoS it trained on, so it says so instead of guessing."*

---

### Act 4: The Novel Attack

**Objective:** The headline. Catch an attack family the model was **never trained on**.

```powershell
python replay/replay.py --scenario act4_botnet_holdout --max-flows 3000
```
Replay checks which model the API is serving and switches it to `cic-holdout-botnet` (trained without any botnet traffic):
`Switched the API model to cic-holdout-botnet-20261002`.

#### Real console output (full 10,000-flow run)
```text
Model: cic-holdout-botnet-20261002
Detections     : 0 Known | 9,916 Novel | 84 Benign
Incidents      : 9 Created, 9,907 Updated
Precision      : 100.00% | Recall: 99.16% | F1: 0.9958
```

#### Dashboard
- **9 incidents, `novel_anomaly`, family `Unknown`, MEDIUM risk 44** (confidence 0.32 x severity 0.92 x burst 1.15 + 0.10 novelty).
- Each is an internal host (172.31.69.x) talking to the same outside address, **18.219.211.138:8080**: the infected machines
  beaconing to their command server. 1,099-1,101 flows each.
- **Brief (template, low confidence band):** *"Possible novel activity from 172.31.69.6 to 18.219.211.138:8080 across 1,101 flows.
  No known attack family matched, but the traffic sits far outside normal behaviour: bwd init win bytes is 219.0 vs baseline 141.0
  and bwd packet length std is ~4x lower than typical. Worth reviewing: check what 172.31.69.6 is doing on port 8080 before escalating."*
- Then run the same command with `--bundle cic-v1`: the same traffic becomes named `Botnet` incidents (MITRE T1071).

#### What the Presenter Says
> *"Judges always ask: 'It's supervised, so how can it catch something it has never seen?' This model was trained without a single
> botnet flow. It still flags 99% of the botnet traffic, and because it can't name the family it says so: novel anomaly, worth
> reviewing. Nine machines all talking to one outside server on port 8080: that is a botnet's command channel. We measured this for
> every attack family; it works for floods, DoS and botnets, and it does not work for internal port scans. That table is in our model card."*

---

### Act 5: Real Internet Traffic and Drift

**Objective:** Leave the lab: real honeypot traffic (LUFlow, Lancaster University), drift detection, unexplained traffic.

```powershell
python replay/replay.py --scenario act5_luflow_drift --max-flows 3000
```
Replay switches the API to `luflow-v1` (trained on June-July 2020; this traffic is from February 2021).

#### Real console output (full 10,000-flow run)
```text
Model: luflow-v1
Detections     : 4,508 Known | 22 Novel | 5,470 Benign
Precision      : 98.64% | Recall: 99.92% | F1: 0.9928
False alarms   : 33 of 5,500 benign flows (0.60%)
Outliers       : 2,098 of 2,099 unexplained flows flagged (not counted in precision / recall)
```

#### Dashboard
- **Drift: ALERT, max PSI 0.33**: normal traffic in February 2021 no longer looks like June-July 2020.
- Detection still holds: precision 98.6%, recall 99.9%, 0.6% false alarms on benign traffic.
- IP addresses in LUFlow are anonymised by the dataset (they show as small numbers); this is not a display bug.

#### What the Presenter Says
> *"Lab data is easy. This is real internet traffic hitting honeypots, seven months after the model was trained. The drift monitor
> raises an ALERT: normal traffic has changed. Detection still holds at 99% precision and recall, so drift is a warning light that
> tells us to recalibrate, not proof the model broke. We tested a label-free recalibration too; on this data it did not help, and we
> say that rather than show it."*

---

### Wrap-Up & Honesty

> *"NetSentinel does not promise zero false positives or magic zero-day detection. Our model card lists where it fails: internal port
> scans and one DDoS tool are not caught when unseen. What it gives a SOC analyst is a short, ranked, explained queue, with the most
> dangerous incident on top and a human always making the call."*

---

## 4. Failure Modes & Emergency Fallback Procedures

| What Breaks | Symptom During Demo | Recovery |
|---|---|---|
| **API down** | Replay stops: `API not reachable at http://127.0.0.1:8000` | Restart the API (terminal 1) and re-run the act. Do **not** switch to `--mock`: its numbers are simulated. |
| **Replay rejected (403)** | `The API rejected the key: set NS_API_KEY...` | `NS_API_KEY` in the replay terminal must equal the API's. |
| **Wrong model loaded** | `The API serves 'X' but this scenario needs 'Y'` | Set `NS_ADMIN_KEY` in the replay terminal (replay switches it) or restart the API with the right `MODEL_REF`. |
| **Everything is slow (~2 s per request)** | Replay crawls at ~100 flows/s at speed 0 | Use `127.0.0.1` instead of `localhost` in `NS_API_URL`. |
| **Azure OpenAI slow / down** | Brief takes a while | The brief service times out after 8 s and returns the template brief (`source: template`). |
| **Streamlit fails** | Browser error | Show `http://127.0.0.1:8000/docs` (Swagger) and the replay console. |
| **Total machine failure** | Nothing works | Play the pre-recorded run of Acts 1-5 (record it from a live run, never from `--mock`). |

---

## 5. Implementation Status

| Feature | Status | Module |
|---|:---:|---|
| Scenario YAMLs (Acts 1-5) | Live-tested with the real bundles | `replay/scenarios/*.yaml` |
| Replay engine (live; `--mock` only labelled SIMULATED) | Implemented & tested | `replay/replay.py` |
| Grounded briefs & template fallback | Implemented & tested | `api/app/services/brief.py` |
| Brief evaluation | Implemented | `api/app/services/brief_eval.py` |
| Risk scoring & MITRE mapping | Implemented & tested | `nscore/contracts/policy.py` |
| API `/v1/flows`, incidents, drift, metrics | Implemented & tested | `api/app/` (M3) |
| Streamlit console | Implemented | `dashboard/` (M4) |
| Azure ML model registry | Tested with a fake client; needs an Azure subscription | `nscore/bundle/azure.py` (M2-12) |
