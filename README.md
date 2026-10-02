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

Source material is in [docs/reference/](docs/reference/).

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt                    # + requirements-ml / -api / -dashboard for your track
cp .env.example .env
pytest -q                                              # contract tests
```

## Repo map
| Path | What | Owner |
|---|---|---|
| `nscore/contracts/` | **Shared schemas, policy, fixtures: the contract between all components** | M3 + all |
| `nscore/features`, `nscore/drift` | train/serve-shared feature transform, PSI | M1 |
| `nscore/detection`, `nscore/bundle` | fusion rule, bundle packaging/loading | M2 |
| `ml/` | offline pipeline | M1, M2 |
| `api/` | FastAPI service | M3 (+ M5 brief) |
| `dashboard/` | Streamlit SOC console | M4 |
| `replay/` | demo traffic replay | M5 |
| `infra/`, `.github/` | compose, Azure, CI | M3 |

## Status
Foundation done: contracts, policy, fusion rule, fixtures, CI. Everything else is in [docs/04_tasks.md](docs/04_tasks.md) and the track issues.
