# 01 — Problem Analysis: PS #26 "Catch the Attack the Signatures Miss"

*Microsoft Innovate 2026 · Focus Area 3 — Cybersecurity (Security Operations) · Advanced*

## The brief, verbatim

> **Scenario** — You're on the network-security team. The signature-based IDS misses novel attacks, so you need an ML model to surface anomalous traffic to analysts.
>
> **Solve this** — An ML classifier that labels traffic normal vs attack (and a few attack types) with honest evaluation, outputting alerts for the SOC — not auto-blocks.
>
> **Data & free tools** — NSL-KDD / CICIDS2017 / UNSW-NB15 datasets; scikit-learn (e.g. Random Forest).
>
> **Make it enterprise-grade:**
> 1. Report precision / recall / false-positive rate / AUC — not just accuracy.
> 2. Handle class imbalance and discuss model drift.
> 3. Alert the SOC rather than auto-blocking traffic.

The brief also sets two rules. **Build the simple version first**, because "a small, working solution beats an ambitious one that doesn't run". And **only test systems you own** or a safe practice environment.

## What the judges will actually probe

| What the brief says | What it really asks | How we answer it |
|---|---|---|
| "signature-based IDS misses **novel** attacks" | Can your system flag something it was **never trained on**? A plain supervised classifier only recognises the attack families it was trained on, so on its own it isn't a full answer. | We add a **novelty detector** (an Isolation Forest trained on benign traffic only) next to the Random Forest. We prove it works with a **Leave-One-Attack-family-Out (LOAO)** evaluation (see [03](03_architecture.md#evaluation-protocol)). |
| "honest evaluation" | Avoid the classic CICIDS2017 traps: random row splits that leak, accuracy on 80% benign data, and SMOTE before the split. | We split by time blocks, report per-class P/R/F1/**FPR**/AUC, apply SMOTE (if we use it) only to training folds, and publish a model card with a limitations section. |
| "precision / recall / **FPR** / AUC" | FPR matters most here, because SOC analysts are drowning in false positives. | We pick thresholds against an **explicit benign-FPR budget**, not the default 0.5. |
| "class imbalance" | Rare classes (Heartbleed: 11 flows, Infiltration: 36) will be memorised rather than learned. | Rare families merge into a `Rare` bucket. We use class weights first and compare SMOTE on train only. |
| "**discuss model drift**" | Both existing docs skipped this. It's an explicit requirement. | We monitor drift live with PSI on the top features plus the predicted attack rate. The dashboard has a drift panel, and the model card has a drift section. |
| "alerts for the SOC — not auto-blocks" | Human in the loop, plus an alert volume a person can actually work through. | Flows are grouped into **incidents** (correlation), ranked by a priority score, and worked through acknowledge / escalate / dismiss-as-FP with an audit trail. Nothing gets blocked. |

## Who has this problem and why it matters (verified figures)

| Claim | Source | Status |
|---|---|---|
| Snort detected only **17%** of zero-day attacks in a 356-attack study (so it missed ~83%). A conservative estimate puts real zero-day detection at 8.2%. | H. Holm, *Signature Based Intrusion Detection for Zero-Day Attacks: (Not) A Closed Chapter?*, HICSS 2014. [ACM DL](https://dl.acm.org/doi/10.1109/HICSS.2014.600) | ✅ Verified. **Note:** the Round 1 doc credits this to "Sabottke et al. (IEEE)", which is wrong. |
| An estimated **46%** of SOC alerts are false positives, and **42%** go uninvestigated. Survey of 300 SOC professionals, June–July 2025. | Microsoft / Omdia, *State of the SOC — Unify Now or Pay Later* (Feb 2026). [Microsoft Security blog](https://www.microsoft.com/en-us/security/blog/2026/02/17/unify-now-or-pay-later-new-research-exposes-the-operational-cost-of-a-fragmented-soc/) | ✅ Verified |
| More than **20%** of CICIDS2017 traces needed rebuilding or relabelling. More than 25% of flows are meaningless artefacts (over 50% for some attack classes). The original CICFlowMeter has TCP flow-construction bugs. A corrected dataset and a fixed CICFlowMeter are published. | Engelen, Rimmer, Joosen, *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study*, IEEE WTMC 2021. [PDF](https://intrusion-detection.distrinet-research.be/WTMC2021/Resources/wtmc2021_Engelen_Troubleshooting.pdf) | ✅ Verified. **Neither existing doc mentions it, but it matters a lot for honest evaluation.** |
| "46–53% of alerts are false positives" / "SANS 2025: FPs are SOC teams' #1 challenge" | Round 1 doc | ⚠️ Couldn't verify the 53% figure or the SANS claim. Use "46% (Microsoft/Omdia 2026)" unless someone finds the primary source. |

**Users:** Tier-1 SOC analysts at organisations that run a signature IDS or SIEM (banks, SaaS companies, MSSPs). Alert queues refill every shift, every day.

## Dataset decision

The PS lists NSL-KDD / CICIDS2017 / UNSW-NB15, but the doc says tools and data are named **"only as examples"**. The only rule is *free and public*. We chose three datasets, each answering a different question (ADR-8 in [03](03_architecture.md)):

| Dataset | Use it for | Why |
|---|---|---|
| **CIC-IDS2017, corrected** (Engelen/Liu et al., IEEE CNS 2022) | **Training + main evaluation** | Modern attacks, 7 families, per-day captures that allow time-aware splits. The labels were manually audited and the flow bugs fixed. |
| **CSE-CIC-IDS2018, corrected** (same authors, same fixed extractor) | **Unseen-network test** + measured drift | Different network, one year later, **identical features** (no mapping needed). Contains attack tools absent from 2017 (DDoS-HOIC, DDoS-LOIC-UDP), so the "novel variant" test uses real traffic. |
| **LUFlow** (Lancaster University honeypots, labelled via CTI) | **Real-world check** | Real traffic, collected continuously since 2020 (real drift). Has an `outlier` label for unexplained traffic, which is the novelty detector's target. Binary labels only and a different schema, so it gets its own feature spec and bundle. |
| NetFlow v3 family (UQ, 2025) | Considered, not chosen | The best "standard enterprise NetFlow" story (53 shared features), but it carries the source datasets' label noise and its extractor isn't fully open. Revisit after I1. |
| UNSW-NB15 (original), NSL-KDD, IDS2025 | Don't use | Dated, known quality issues, or (IDS2025) just CICIDS2017 rebalanced with its label errors still in. |

CICIDS2017 days: Mon = benign only · Tue = FTP/SSH brute force · Wed = DoS variants + Heartbleed · Thu = web attacks + infiltration · Fri = botnet, port scan, DDoS. **This layout drives our split design** (see [02](02_doc_validation.md) and [03](03_architecture.md)).

## Scope

**In scope:** offline training on corrected CIC-IDS2017 · cross-network evaluation on CSE-CIC-IDS2018 · real-traffic validation on LUFlow · fusion of supervised and novelty detection · SHAP explanations · incident correlation and prioritisation · SOC console · Azure ML model registry · Azure OpenAI incident briefs · drift monitoring · replay-based live demo.

**Out of scope (say so explicitly in the deck):** inline blocking · claims about real zero-days (we demonstrate *families the model never saw*, which is a controlled proxy) · production-scale throughput · live capture on networks we don't own.

## Success criteria for Round 2

1. Replay **real 2018 traffic from an unseen network** (including the never-trained DDoS-HOIC). The drift monitor fires, recalibration recovers, and the unseen attack is still flagged with an explanation. Backup: the holdout-family bundle shows a `Novel anomaly`.
2. The model card reports per-class P/R/F1/FPR/AUC, the LOAO table, the operating FPR and its limitations, and every number is reproducible from the repo.
3. One alert storm (DDoS replay) produces a small number of incidents, not thousands of rows.
4. The drift panel visibly reacts when the traffic distribution shifts.
5. The whole demo works with Azure unreachable: cached bundle plus template briefs.
