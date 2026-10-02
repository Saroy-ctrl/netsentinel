# NetSentinel model card

*Sections 1–2 (data, intended use) are written by M1 and reproducible from `docs/data_profile.md`. Sections 3, 4, 5 and 7 are written by M2
from the evaluation reports (not from memory); section 6 (risk scoring) is M5's.*

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

## 3. Models

All numbers below are produced by `ml/train/*` and reproduced in `docs/experiments.md`; bundles are built by `ml/train/build_bundles.py`.

| Part | Trained on | Output | Settings |
|---|---|---|---|
| `rf_binary` | 3.52M working-sample train flows (2.5M benign + up to 300k per attack tool) | p(attack) | RandomForest: 100 trees, depth 16, 100 samples per leaf, 20% of features per split, no class weights. Chosen by tool-holdout recall (experiments §6); ~5 MB |
| `rf_multiclass` (family head) | attack train flows | family + per-family probabilities; **confidence = max probability** | RandomForest: 100 trees, 2 samples per leaf. 6 families |
| `iforest` | benign train flows only | anomaly percentile | **Not shipped in CIC bundles**: ROC-AUC 0.70-0.87 and ~0 recall at a usable false-alarm rate (experiments §4). Shipped in LUFlow bundles only |
| `transformer` | train split only | 46 scaled features | per-group clipping, train-median imputation |

**Verdict rule** (`nscore/detection/fusion.py`): `p_attack >= tau_binary` and family confidence `>= tau_family` -> `known_attack` with that family;
`p_attack >= tau_binary` and confidence `< tau_family` -> `novel_anomaly` (family `Unknown`, closest family reported); otherwise benign.

**Thresholds in `cic-v1`:** `tau_binary = 0.137` (the lowest value whose benign false-alarm rate on validation is <= **0.1%**),
`tau_family = 0.987` (2% of familiar validation attacks fall below it). The whole trade-off, budgets 0.01%-1%, ships as `operating_curve.json`.

**Why a 0.1% budget:** at this network's scale (~330k benign flows an hour) 1% is thousands of false alarms an hour and cuts precision at natural
prevalence to ~87-91%. Even 0.1% is hundreds of false-alarm flows an hour before the correlator groups them into incidents.

**Explanations:** exact TreeSHAP on `rf_binary`, ~50-110 ms per flow (a fast mode uses the first 25 trees), so the API explains a few
representative flows per incident. Most influential features overall: `bwd_init_win_bytes`, `fwd_packet_length_std`, `flow_bytes_per_s`,
`fwd_psh_flags`, `flow_iat_mean` (`global_importance.json`).

**Reproducibility:** bundles carry the sha256 of every file and refuse to load if anything is missing or edited; the serving path
(`DetectionEngine`) agrees with the training pipeline on 100.0% of 20,000 test flows.

## 4. Evaluation

Test split = later time blocks of the same lab network (never seen by training, thresholds, or tuning). Precision and counts are weighted to the
natural class balance (benign was sub-sampled). Source: `cic-v1` `evaluation_report.json`, `docs/experiments.md` §7.

**In-distribution, `cic-v1` at the 0.1% budget:** attack recall 99.99%, test benign false-alarm rate **0.20%** (twice the budget: validation and test
blocks differ, so budgets are targets, not guarantees), precision at natural prevalence 97.4%, binary ROC-AUC 0.99999, macro-F1 0.953 over the 8 verdict
labels. Recall per family: Botnet 100%, BruteForce 100%, DoS 100%, DDoS 100%, Infiltration 99%, WebAttack 89%. WebAttack has only
36 test flows (recall 95% CI 0.62-0.88): do not quote it. **This is the easy number**: in-distribution accuracy is saturated (experiments §1) and says little about unseen attacks.

**Generalisation (the headline; 3 seeds; both heads retrained without the held-out attack; recall at the 0.1% benign-FPR budget unless stated):**

| held out | recall @0.1% | @0.05% | @0.5% | read |
|---|---|---|---|---|
| DDoS-HOIC (tool) | 100% | 100% | 100% | caught (untouched by tuning) |
| DoS Hulk (tool) | 100% | 100% | 100% | caught |
| DoS GoldenEye / Slowloris (tools) | 100% | 92% / 89% | 100% | caught |
| DoS (family) | 85% | 83% | 94% | mostly caught |
| DDoS (family) | 79% | 78% | 81% | mostly caught |
| BruteForce (SSH, family) | 98% | 29% (range 0-74%) | 100% | caught at 0.1%, knife-edge below |
| Botnet (family) | 66% (range 51-76%) | 1% | 99% | needs a looser budget |
| Infiltration (internal Nmap scan, family) | 1% | 1% | 9% | **not caught** |
| DDoS-LOIC-HTTP (tool) | 1% | 1% | 1.5% | **not caught** |

Detections the family head cannot place are labelled `novel_anomaly`; familiar attacks are mislabelled that way ~2% of the time by construction.

**LUFlow (real honeypot traffic, 7 later months, frozen model):** recall 99.8-99.9%, benign false-alarm rate 0.17-0.71% against a 0.5% budget,
ROC-AUC 1.000. This is the easy problem (bots vs known production services; labels come from threat intelligence), a real-traffic and drift check
rather than a headline. The forest flags ~100% of the unexplained `outlier` flows; the benign-only IsolationForest flags 1-3%.

## 5. Drift

PSI per feature against the training distribution (`nscore/drift/psi.py`; bins and reference ship in the bundle; live thresholds 0.10 watch, 0.25 alert).
On LUFlow, max PSI per month: 2020-06 0.14, 07 0.39, 08 0.20, 09 0.14, 10 0.10, 11 0.18, 12 0.36, 2021-01 0.12, 02 0.10: six months `watch`, two `alert`
(2020-07 and 2020-12), one `ok`. Recall and false-alarm rate did **not** move with it, so PSI is a *warning light* that the input distribution changed,
not a measure of accuracy. Label-free recalibration (refit the IsolationForest and thresholds on a recent benign window) changed FPR by a few tenths of a
percent in both directions with no consistent gain; it is available but not claimed as an improvement.

## 6. Risk scoring (owner: M5)

*Weights and their reasons from `docs/threat_model.md`; worked examples.*

## 7. Limitations and failure modes

Everything in 1.5, plus:

1. **Lab network, scripted attacks.** Strong held-out results are a controlled proxy for "attacks the signature missed", not evidence about a production network or real zero-days.
2. **Does not generalise to everything.** Unseen internal Nmap scans (Infiltration) and the LOIC-HTTP tool are missed at every budget; botnet needs a 0.1-0.5% budget; SSH brute force is
   knife-edge below 0.1% (recall 0-74% across seeds at 0.05%). Always show seed ranges, never a single run.
3. **Budgets are targets.** Test false-alarm rate was ~2x the validation budget at 0.1% (0.20%). Re-measure on the deployment network and use the operating curve.
4. **False alarms still need grouping.** 0.1% of ~330k benign flows an hour is hundreds of flows an hour; the correlator turns these into fewer incidents, but that has not been measured end to end.
5. **WebAttack has 283 flows in total (36 in test)**: its numbers are unreliable and it is excluded from the leave-one-out study.
6. **The novelty signal is family-head confidence**, which separates unfamiliar from familiar attacks on the 2018 data (ROC-AUC 0.997-1.000) but is untested on other networks. The benign-only IsolationForest failed on CIC flows and is not shipped there.
7. **Flow features only.** No payload and no encrypted-content inspection. Never auto-block: decisions stay with the analyst.
8. **Version coupling.** Bundles are pickled scikit-learn 1.9.1 models; the loader warns on a version mismatch and checks sha256 integrity on every load.
9. **Risk scoring and live behaviour** are documented by M5 (section 6) and measured in the replay demo, not here.
