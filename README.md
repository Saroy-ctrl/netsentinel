# NetSentinel

**An ML layer that flags what signature IDS misses: explained, prioritised SOC incidents, never auto-blocks.**

Microsoft Innovate 2026 · Problem Statement **#26 — Catch the Attack the Signatures Miss** (Cybersecurity / Security Operations)

```
CICFlowMeter flows ──► RF (known attack families) ─┐
                   └─► family head (confidence = familiar?) ─► SHAP ─► incidents ─► SOC console
                                                                             │            │
                                     Azure ML registry ◄── offline training  │   Azure OpenAI brief
                                                                       drift monitor (PSI)
```

## Why this design wins
- **Catches attacks it was never trained on, and says so.** Measured with leave-one-family-out and tool-holdout tests: the supervised forest detects unseen floods, DoS and botnet traffic at strict false-alarm budgets, and low family confidence labels the alert *unfamiliar*. We also tried a benign-only anomaly detector first; it didn't work on these flows, so we dropped it (`docs/experiments.md`). Internal Nmap scans and the LOIC-HTTP tool are *not* caught when unseen, and SSH brute force / botnet only at looser false-alarm budgets; we say that.
- **Tested beyond the lab.** Trained and tested on corrected CSE-CIC-IDS2018 (a 420-machine network, 10 days, many attack tools), then shown working live on *real* honeypot traffic (LUFlow), where drift is measured, not assumed.
- **Honest numbers.** Audited labels, a time-blocked split, per-class P/R/F1/**FPR**/AUC, thresholds set by an explicit false-positive budget, and a model card with limitations.
- **Reduces alert fatigue instead of adding to it.** Flows are grouped into incidents, risk-scored (confidence × severity × burst → HIGH / MEDIUM / LOW) and mapped to MITRE ATT&CK.
- **Human in the loop.** Acknowledge / escalate / dismiss-as-FP, with an audit trail and live analyst-confirmed precision.
- **Drift-aware.** Live PSI monitor with a retraining trigger.
- **Real Azure.** Azure ML model registry (with a local cache fallback) and Azure OpenAI incident briefs (with a template fallback).

## Docs: read in this order
1. [docs/01_problem_analysis.md](docs/01_problem_analysis.md): the PS, what the judges probe, verified facts, dataset choice
2. [docs/02_doc_validation.md](docs/02_doc_validation.md): review of the Round 1 doc and the NetSentinel build plan
3. [docs/03_architecture.md](docs/03_architecture.md): **the final framework**
4. [docs/04_tasks.md](docs/04_tasks.md): **team tracks M1–M5 and ordered task checklists**
5. [CONTRIBUTING.md](CONTRIBUTING.md): branches, PRs, contract-change rule

Results and evidence (generated from the code, so they match the models):
- [docs/model_card.md](docs/model_card.md): data, models, evaluation, drift, limitations
- [docs/experiments.md](docs/experiments.md): every experiment behind the design, including what failed
- [docs/data_profile.md](docs/data_profile.md): dataset audit and split counts
- [docs/azure_setup.md](docs/azure_setup.md): Azure ML workspace, registering and pulling bundles

Source material is in [docs/reference/](docs/reference/).

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt                    # + requirements-ml / -api / -dashboard for your track
cp .env.example .env
pytest -q                                              # contract, bundle, metrics and registry tests
```

### Get a model bundle (the API and dashboard load one)
```bash
python scripts/make_mock_bundle.py                     # no data needed: artifacts/bundles/mock-cic, mock-luflow
```
Real bundles (`cic-v1`, `cic-holdout-botnet`, `luflow-v1`, `luflow-recal`) are built from the data, so they are not in git
(`artifacts/` is gitignored). Ask the M2 owner for the folders, pull them from Azure ML (`docs/azure_setup.md`), or rebuild:
```bash
pip install -r requirements-ml.txt
# 1. build the cleaned data, splits and working sets (10 GB download for 2018): follow data/README.md
python -m ml.train.build_bundles                       # cic-v1       (~10 min on a laptop)
python -m ml.train.build_bundles --holdout Botnet      # cic-holdout-botnet (the live-demo "never saw a botnet" model)
python -m ml.train.luflow                              # luflow-v1, luflow-recal + month-by-month study
python -m ml.train.make_experiments_doc                # regenerate docs/experiments.md
```
```python
from nscore.bundle.loader import load_bundle
from nscore.detection.engine import DetectionEngine
bundle = load_bundle("local:artifacts/bundles/cic-v1")     # or "azureml:netsentinel-bundle@latest"
det = DetectionEngine(bundle).detect(flows_df)             # verdict, p_attack, family, closest_family, confidence
```

## Repo map
| Path | What | Owner |
|---|---|---|
| `nscore/contracts/` | **Shared schemas, policy, fixtures: the contract between all components** | M3 + all |
| `nscore/features`, `nscore/drift` | train/serve-shared feature transform, PSI | M1 |
| `nscore/detection`, `nscore/bundle` | detection engine, fusion rule, SHAP explainer, bundle packaging/loading, Azure ML registry | M2 |
| `ml/` | offline pipeline: data (M1), training, evaluation, experiments (M2) | M1, M2 |
| `scripts/` | mock bundles, Azure registration, PDF export | M2 |
| `api/` | FastAPI service | M3 (+ M5 brief) |
| `dashboard/` | Streamlit SOC console | M4 |
| `replay/` | demo traffic replay | M5 |
| `infra/`, `.github/` | compose, Azure, CI | M3 |

## Status
| Track | State |
|---|---|
| Foundation (contracts, policy, fixtures, CI) | done |
| **M1** Data & Features | **done, merged** (#6): cleaned datasets, splits, feature specs, PSI, replay samples |
| **M2** ML Modeling & MLOps | **done, merged** (#7): models, evaluation, SHAP, bundles, Azure ML registry code, model card. Real Azure registration still needs the team's subscription |
| **M3** Backend & Platform | **done, merged** (#11, fixes #10, #13): API, correlator, drift monitor, auth, Docker/ACA assets |
| **M4** SOC Console | **done, merged** (#9, fix #12): Streamlit console, five pages |
| **M5** Security, GenAI & Demo | **on branch `final`**: Azure OpenAI briefs with template fallback, brief evaluation, replay engine + 5 live-tested demo acts, threat model, demo script, pitch |

Run the demo: [docs/demo_script.md](docs/demo_script.md) (API + dashboard + replay, all local; every number in it comes from a live run).

Headline numbers (test split, details and limits in the model card): 99.99% attack recall at a 0.1% benign false-alarm budget on known
attacks; on attacks held out of training, floods/DoS tools 100%, DoS/DDoS families 79-85%, botnet 66% (99% at a 0.5% budget), while internal
Nmap scans and LOIC-HTTP are missed.
