# 02 — Review of the Two Existing Documents

| Doc | Author | Verdict |
|---|---|---|
| **A.** `Microsoft_Innovate_2026_Round1_Content.pdf` | earlier Claude session | Right problem statement, right direction. **It has a wrong citation, unverified figures, a pitch that overclaims, and it misses drift.** Fix before submitting. |
| **B.** `NetSentinel_Architecture_Build_Plan.pdf` | teammate | **A strong base. We keep about 70% of it.** Its leakage handling is good. Its split design is flawed, and it lacks novelty detection, incident correlation and drift monitoring. |

Both target **PS #26**. The final framework in [03_architecture.md](03_architecture.md) builds on Doc B.

> **Update (2 Oct):** since this review the team chose **corrected CSE-CIC-IDS2018** for train/val/test and **LUFlow** as a real-traffic showcase (ADR-8), and adopted the teammate's **Risk Scoring Pipeline** doc as the base of the risk engine (ADR-9). Both docs below were written around CICIDS2017; every issue still applies, because 2018 has the same one-attack-per-day layout and the same original-release label problems. Fixes below are worded for the final plan.

---

## Doc A — Round 1 idea submission

### What it gets right
- The problem framing is correct: signature gaps plus alert fatigue, with Tier-1 SOC analysts as the users.
- Human in the loop with "never auto-block", which matches the PS.
- Per-class precision/recall/FPR/AUC, so it isn't relying on accuracy alone.
- SHAP explanations and Azure OpenAI briefs, a good fit for a Microsoft hackathon.

### Issues and fixes

| # | Issue | Severity | Fix |
|---|---|---|---|
| A1 | The ~83% Snort figure is credited to "Sabottke et al. (IEEE)". Sabottke et al. wrote about vulnerability disclosure on Twitter. The figure is from **Holm, HICSS 2014** (Snort detected 17% of zero-days). | 🔴 A judge who checks this will lose trust in everything else | Change the citation to Holm 2014. Better wording: "Snort detected only 17% of zero-day attacks (Holm, 2014)". |
| A2 | "46–53% false positives" and "SANS 2025 #1 challenge" | 🟠 | 46% is verified (Microsoft/Omdia 2026). The 53% and SANS claims weren't verified, so drop them or find the primary source. |
| A3 | **No mention of model drift**, even though the PS asks for it outright ("discuss model drift"). | 🔴 Misses a stated requirement | Add: "PSI-based drift monitoring on live traffic, with a retraining trigger". |
| A4 | The one-line pitch says a supervised Random Forest "flags what signature IDS misses". A supervised RF only recognises attack families it was trained on, so the claim isn't backed up as written. | 🔴 The first hard question in Q&A | Add the novelty layer (Isolation Forest trained on benign only) and the LOAO evaluation as evidence. |
| A5 | "Live PCAP" in the flow diagram | 🟠 Overclaims | Say "PCAP → CICFlowMeter → replay". Live capture is a stretch goal on our own VMs only. |
| A6 | "First-pass Random Forest baseline trained…" | 🟠 | Keep this only if it's actually true when we submit. |
| A7 | The tech stack lists "Streamlit / React" | 🟡 | Pick Streamlit. Add React only after the demo works end to end. |
| A8 | One alert per flow would *add* to the alert-fatigue problem the pitch complains about. | 🟠 | Group flows into incidents (correlation by source/destination/family in a time window). |
| A9 | No mention that CICIDS2017 has known label errors. Single lab dataset only. | 🟠 | "Trained and tested on corrected CSE-CIC-IDS2018, shown working on real traffic (LUFlow)" (ADR-8). It earns credibility. |
| A10 | Template placeholders (team name, IDs, members) are still unfilled. | 🟡 | Fill them in. |
| A11 | Dataset references are CICIDS2017 / NSL-KDD / UNSW-NB15 throughout (problem framing, tech stack, "what we have started", feasibility, references). | 🟠 | Switch to corrected CSE-CIC-IDS2018 + LUFlow. Cite Liu et al. (CNS 2022) for the corrections and the LUFlow paper. Update "what we have started" to what's actually done on 2018. |
| A12 | No mention of how alerts are ranked. | 🟡 | One line from the team's risk doc: "risk = confidence × severity, so a sure-but-harmless port scan ranks below a less-sure infiltration". |

---

## Doc B — NetSentinel architecture & build plan

### What it gets right (kept as-is)
- **Separate offline and online pipelines**: retraining never touches serving code. This is the single best decision in the doc.
- IPs, Flow ID and Timestamp are dropped from model features but kept as metadata.
- Inf/NaN handling with counts recorded, plus deduplication.
- SMOTE **after** the split, on train only. Class weights for ultra-rare classes. Rare classes merged.
- Per-class metrics, confusion matrix saved as an artifact, and a limitations note.
- The feature column order is saved, and feature code is **shared between train and serve**.
- The Azure ML registry is used for real (pull by `name:version`), not just name-dropped.
- Briefs are lazy and cached, hedge at low confidence, and never block the queue.
- A pre-recorded fallback video, and careful wording ("a variant not well represented in training", not "a zero-day").
- The Model Info page is the thing that makes the system look real to a judge.

### Issues and fixes

| # | Issue | Severity | Fix in final architecture |
|---|---|---|---|
| B1 | **The day-based split ("train Mon–Thu, test Fri") breaks multiclass evaluation.** Friday is the only day with Botnet, PortScan and DDoS, so those classes never appear in training and the multiclass head can't predict them. Monday is benign only. **2018 has the same problem**: each attack runs on one or two specific days (e.g. Botnet only on 02-03). | 🔴 | Use two separate protocols. **(a)** A time-blocked split per (day, label), 70/15/15, **with a 60 s purge at block boundaries**: each class keeps its contiguous time blocks, so session leakage is limited and every class still appears in train, val and test. **(b)** LOAO, which turns "an attack family the model has never seen" into a proper, deliberate experiment. |
| B2 | **There's no way to detect novel attacks.** RF binary plus RF multiclass is fully supervised. | 🔴 Core PS claim | *Original fix:* add an Isolation Forest trained only on benign flows. **Revised after measurement:** the IForest had ~0 recall on CIC flows; instead the supervised RF's generalisation is measured with leave-one-out tests and the family head's low confidence marks an attack as *unfamiliar* (`novel_anomaly`). See `docs/experiments.md` and ADR-1. |
| B3 | **One alert per flow.** Replaying a DDoS creates thousands of queue rows. | 🔴 Wrecks the demo and the pitch | Add an **incident correlator** that groups by (src_ip, dst_ip, family) in a 5-minute window and upserts with flow_count, max confidence and aggregated SHAP. The queue shows incidents, not flows. |
| B4 | **No drift handling** (an explicit PS requirement). | 🔴 | Store a drift reference (quantile bins of the top features) in the bundle. The API computes PSI over a rolling window and serves `/v1/drift`. Add a dashboard panel and a model-card section. |
| B5 | Thresholds aren't discussed (implicitly 0.5). | 🟠 | Choose `tau_binary` and `tau_anomaly` on validation against an explicit benign-FPR budget (e.g. ≤1%), and report that operating point. |
| B6 | `/flows/ingest` "extracts features". PCAP → flow needs CICFlowMeter, which is an offline Java tool, not something the API can run. | 🟠 | The API accepts **flow records that already have features** (`FlowRecord` contract). PCAP → CSV is an offline step in `replay/`. |
| B7 | Doesn't mention the CICFlowMeter and CIC-dataset label errors. | 🟠 | Use the **corrected CSE-CIC-IDS2018** and the fixed CICFlowMeter (Liu/Engelen et al., CNS 2022). The original 2018 CSVs also lack IP columns on most days, which breaks incident grouping. |
| B8 | Proposes serializing the SHAP explainer with the model. | 🟡 | Rebuild the `TreeExplainer` from the model when loading. That's cheap, and pickled explainers break across shap versions. |
| B9 | Pulling from Azure ML at startup makes it a single point of failure during the demo. | 🟠 | Keep a local cache with sha256 checks. If Azure is unreachable, load the cached bundle and log a warning. |
| B10 | Brief failure "doesn't block", but there's no fallback content. | 🟡 | Add a deterministic template brief built from the same structured fields (`source: "template"`). |
| B11 | The "priority score" is mentioned but never defined. | 🟡 | Now the **risk engine** in `nscore/contracts/policy.py`, based on the teammate's Risk Scoring Pipeline doc: confidence × expected severity × burst, plus a novelty bonus, giving HIGH / MEDIUM / LOW (ADR-9). |
| B12 | `Destination Port` is a feature in the CICIDS CSVs, and the doc doesn't say whether to use it. | 🟡 | Run the experiment both ways and document it. Ports carry real signal but also capture quirks of the dataset. |
| B13 | SMOTE on ~2.8M rows plus RandomizedSearchCV "trains in minutes on a laptop" is optimistic. | 🟡 | Default to class weights. Test SMOTE inside the CV folds (imblearn pipeline) on a down-sampled benign set. Set a time budget. |
| B14 | The schema has `alerts` per flow, with no incidents and no drift table. | 🟠 | New schema: `flows`, `incidents`, `analyst_actions`, `drift_snapshots` (see 03). |
| B15 | No authentication on ingest, and actions carry only a free-text analyst name. | 🟡 | Ingest needs an API key. Actions need an `X-Analyst` header and are logged in an audit trail. |
| B16 | The team split has 4 tracks, but we have 5 people, and the tracks run in sequence (Phase 8 is the first integration). | 🟠 | Contract-first: shared schemas and fixtures from day 0, plus a mock API and a mock bundle, so all 5 tracks start at once. See [04_tasks.md](04_tasks.md). |
| B17 | No live feedback loop. | 🟡 | `dismiss_fp` and `confirm` actions feed a live **analyst-confirmed precision** metric. This shows the honesty is measurable. |

### What carries over from Doc B
- Kept: §1, §2 (extended), §3.2–3.3, §3.5–3.9 (with B5 and B8 applied), §6, §7, §8 (with B6 applied), §9 Phases 0 and 9–10.
- Replaced: §3.4 split strategy (B1), §4 schema (B14), §5 endpoint set (versioned `/v1`, incidents instead of alerts).
- Added: leave-one-out evaluation, family-confidence novelty signal, correlator, drift, threshold calibration, contracts, fallback paths.
