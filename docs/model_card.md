# NetSentinel model card

*Sections 1–2 (data, intended use) are written by M1 and reproducible from `docs/data_profile.md`. Sections 3–7 are
placeholders owned by M2 / M5 and must be filled from the evaluation reports, not from memory (honesty rule).*

## 1. Data

### 1.1 Datasets and why

| Dataset | Role | Source / version | Why this one |
|---|---|---|---|
| **CSE-CIC-IDS2018, corrected** | train, validate, test | Liu, Engelen, Lynar, Essam, Joosen, IEEE CNS 2022. `CSECICIDS2018_improved.zip`, 10.4 GB, last modified 2023-04-03. sha256 in `data/README.md` | Large, varied AWS network (420 machines, 30 servers, 50 attackers), 10 capture days, seven attack scenarios with many tools. Labels were manually audited and the CICFlowMeter bugs fixed; the original release has labelling and flow-construction errors, so we do **not** use it |
| **LUFlow** | real-traffic showcase and drift study (own model) | Lancaster University honeypots + threat-intelligence labelling, published continuously since 2020-06. We use **8 evenly spaced days per month, 2020-06 → 2021-02 (72 days)** | Real internet attack traffic, not a lab. Has `outlier` = abnormal but unexplained, which is what the novelty detector targets |

The problem statement lists NSL-KDD, CICIDS2017 and UNSW-NB15 *as examples*; any free public dataset is allowed. Decision record: ADR-8
in `docs/03_architecture.md`.

### 1.2 What we did to the data (counts: `docs/data_profile.md`)

| Step | 2018 | LUFlow |
|---|---|---|
| Raw flows | 63,195,145 | 63,011,836 (72 days) |
| Exact duplicates removed (before splitting, so identical flows cannot sit in train and test) | 17,994,579 (28.5%) | 18,081,053 (28.7%) |
| Relabelled benign (`Attempted Category != -1`, the authors' recommendation) | 306,237 | n/a |
| `time_start` repaired (source dropped leading zeros of the microsecond part) | n/a | 6,294,766 rows, plus 986 dropped as > 2 days off |
| Non-finite values (Infinity → NaN, then train-median imputation) | 57 rows | 0 |
| **Clean flows** | **45,200,566** | **44,929,797** |

Features are float32. Identifiers (IPs, source port, timestamp, file bookkeeping) are metadata, never model inputs. 2018 keeps
**46 of 82** candidate features and LUFlow **9 of 9** after dropping constants and pairs with Spearman |ρ| > 0.95 (the more basic
feature wins ties). Clip ranges are computed per class group so no attack's own tail is flattened.

### 1.3 Labels

* **2018 families:** `DoS` (Hulk, GoldenEye, Slowloris), `DDoS` (HOIC, LOIC-HTTP, LOIC-UDP), `BruteForce` (**SSH-Patator only**: every
  FTP-Patator flow is `Attempted`), `Infiltration` (**99.7% of its raw flows are the internal Nmap port scan**), `Botnet` (Ares),
  `WebAttack`, `BENIGN`. DoS SlowHTTPTest is absent from the corrected release.
* **`WebAttack` has only 283 flows** in total. It remains a named family with a low-support caveat, is excluded from the
  leave-one-family-out evaluation, and its per-class metrics must be shown with wide uncertainty.
* **LUFlow labels:** `benign` (known production services), `malicious` (matched threat intelligence), `outlier` (abnormal, not
  explained). **`outlier` is never a supervised label**, and "malicious" means *matched a feed at labelling time*, which lags real
  attacks. There are no attack families, so the LUFlow model is binary plus the novelty detector.

### 1.4 Splits (no random row splits anywhere)

* **2018:** within every (day, family, tool) group, flows are ordered by timestamp and split 70% / 15% / 15% into
  train / validation / test, with the flows within `min(60 s, 2% of the group's span)` of each boundary purged so one attack
  session cannot straddle two sets. Reasons: each attack lives on one or two days (a day split would remove whole families from
  training) and tools inside a family run at different times (LOIC-UDP vs HOIC), so each needs its own test block. Everything is
  fitted on train only (scaler, imputation medians, clip ranges, thresholds on validation). Leave-one-family-out and tool-holdout
  folds are generated from the same split.
* **LUFlow:** the first two months (2020-06, 2020-07) are split the same way. Every later month is a drift test set; the first 20% of
  each month's time span supplies a label-free benign "recent known-good traffic" window for refitting only the IsolationForest and
  thresholds. 60 s purge at the boundary.
* Working samples with a fixed seed (42) keep training laptop-sized: up to 300,000 flows per attack tool plus 2.5M benign for
  training, every attack flow plus 1.5M benign for evaluation.

### 1.5 Known data limitations (say these out loud)

1. **Lab-generated attacks.** 2018's attacks are scripted from a few machines on a controlled AWS network; benign traffic is generated
   by user profiles. Results are not evidence of performance on an unseen production network.
2. **Attacks are 7.7% of clean 2018 flows** (3.50M of 45.2M), and some are very homogeneous (Hulk is 98% of DoS), so per-family
   numbers depend heavily on a few tools.
3. **Duplicates were removed globally**, which removes the volume signal of repeated scans (it does not affect behaviour-based features).
4. **LUFlow is honeypot-biased**: it over-represents scanning and brute-force bots and under-represents everything else, and its labels
   come from threat-intelligence feeds that can be late or wrong.
5. **LUFlow has 9 features**, so its absolute numbers will be lower than 2018's. It is a drift and real-traffic check, not a headline accuracy.
6. **Only 8 days per month** of LUFlow are used.
7. **Timestamps** in 2018 are UTC and shifted 4 hours from the times printed on the CIC page.

## 2. Intended use

SOC decision support: rank and explain suspicious flows for a human analyst. **Not for automatic blocking.** Out of scope: payload
inspection, encrypted-content classification, and any claim about real zero-day attacks (we evidence behaviour on attack families or tools
held out of training, which is a controlled proxy).

## 3. Models (owner: M2)

*To be filled from `evaluation_report.json`: RF binary, RF multiclass, IsolationForest, thresholds and the false-positive budget.*

## 4. Evaluation (owner: M2)

*Per-class precision / recall / F1 / FPR / AUC, confusion matrix, leave-one-family-out table, HOIC tool holdout, LUFlow month-by-month results.*

## 5. Drift (owner: M2, M3)

*Measured PSI per feature on LUFlow months, recalibration result, live monitor thresholds (0.10 watch, 0.25 alert).*

## 6. Risk scoring (owner: M5)

*Weights and their reasons from `docs/threat_model.md`; worked examples.*

## 7. Limitations and failure modes (owner: M2, M5)

*Everything in 1.5, plus model-specific findings and the Q&A prepared answers.*
