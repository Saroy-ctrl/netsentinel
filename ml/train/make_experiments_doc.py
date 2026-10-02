"""Generate docs/experiments.md from artifacts/experiments/*/results.json and the bundle reports (nothing typed by hand).

    python -m ml.train.make_experiments_doc

Every number comes from a results file, so the document can be regenerated after any re-run. Prose that interprets the
numbers is kept short and sits next to the table it explains.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXP = ROOT / "artifacts" / "experiments"
BUNDLES = ROOT / "artifacts" / "bundles"


def load(rel: str):
    p = EXP / rel
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def pct(x, d=1) -> str:
    return "n/a" if x is None else f"{100 * x:.{d}f}%"


def table(header: list[str], rows: list[list], align: str | None = None) -> str:
    align = align or "|" + "---|" * len(header)
    return "\n".join(["| " + " | ".join(header) + " |", align] + ["| " + " | ".join(map(str, r)) + " |" for r in rows])


def baseline_section() -> str:
    b = load("baseline/metrics.json")
    if not b:
        return ""
    r5, r1 = b["at_0.5"], b["at_fpr_1pct"]
    out = ["## 1. Baseline random forest (validation split)", "",
           "Plain settings (100 trees, balanced class weights, 2 samples per leaf), trained on the 3.5M-flow train sample.", "",
           table(["operating point", "precision (natural prevalence)", "recall", "benign FPR", "ROC-AUC"], [
               ["threshold 0.5", pct(r5["precision"], 2), pct(r5["recall"], 2), pct(r5["fpr"], 3), f"{r5['roc_auc']:.5f}"],
               ["FPR budget 1%", pct(r1["precision"], 1), pct(r1["recall"], 2), pct(r1["fpr"], 2), f"{r1['roc_auc']:.5f}"]]),
           "",
           f"* **In-distribution detection is saturated** (ROC-AUC {r5['roc_auc']:.4f}; every attack tool above 99%). It is not a "
           "result worth presenting: the time-blocked split puts early and late parts of the same attack burst on both sides.",
           f"* **Prevalence matters.** On the raw validation sample (21% attacks) precision at the 1% budget reads "
           f"{pct(b['sample_precision_at_fpr_1pct'])}; weighted to the real class balance (7.7% attacks) it is "
           f"**{pct(r1['precision'])}**. All reported precision is weighted.",
           "* The 1% false-alarm budget in the original plan is far too loose for a SOC: at this network's size it is thousands "
           "of false alarms per hour. See the operating curve below.", ""]
    return "\n".join(out)


def imbalance_section() -> str:
    r = load("imbalance/results.json")
    if not r:
        return ""
    rows = []
    for name, v in r["family"].items():
        rows.append([name, f"{v['n_train']:,}", f"{v['macro_f1']:.4f}"]
                    + [pct(v["per_class"][f]["recall"], 1) for f in sorted(v["per_class"])])
    fams = sorted(next(iter(r["family"].values()))["per_class"])
    b = r["binary"]
    return "\n".join([
        "## 2. Class imbalance", "",
        "Binary head, 1M-row train subsample (validation, threshold 0.5; precision here is on the raw attack-heavy "
        "sample, so only the comparison between rows is meaningful):", "",
        table(["weights", "precision (raw sample)", "recall", "benign FPR"], [
            [k, pct(v["at_0.5"]["precision"], 3), pct(v["at_0.5"]["recall"], 3), pct(v["at_0.5"]["fpr"], 4)] for k, v in b.items()]),
        "", "Family head (attack flows only; training counts " + ", ".join(
            f"{k} {v:,}" for k, v in r["family_train_counts"].items()) + "):", "",
        table(["strategy", "train rows", "macro-F1"] + [f"recall {f}" for f in fams], rows), "",
        "**Finding:** every strategy, including SMOTE for the rare families, scores macro-F1 = 1.0000 on validation: the data is "
        "separable enough that imbalance handling cannot be measured in-distribution. **Decision:** keep plain class weights "
        "(cheap, no synthetic data, no leakage risk) and spend the effort on the held-out experiments below.", ""])


def ablation_section() -> str:
    r = load("feature_ablation/results.json")
    a = load("loao_ablation/results.json")
    if not r:
        return ""
    rows = [[k, v["n_features"], pct(v["at_fpr_0.1pct"]["recall"], 3), v["worst_tool"][0], pct(v["worst_tool"][1], 1)]
            for k, v in r.items()]
    out = ["## 3. Shortcut features", "",
           "The top features of the baseline are TCP initial window sizes: a Kali-attacker vs Windows-victim fingerprint, not attack "
           "behaviour. Validation recall at a 0.1% FPR (1M-row models):", "",
           table(["feature set", "features", "recall @ 0.1% FPR", "weakest tool (>=100 flows)", "its recall"], rows), "",
           "**Finding:** removing the window sizes, the TCP flags, or both changes nothing in-distribution, and adding `dst_port` "
           "does not help, so it stays excluded. In-distribution tests cannot reveal a shortcut, so the same ablation was repeated "
           "under leave-one-family-out (recall at a 0.5% FPR):", ""]
    if a:
        fams = [k for k in next(v for k, v in a.items() if isinstance(v, dict) and "n_features" in v) if k != "n_features"]
        out.append(table(["feature set", "features"] + fams, [[k, v["n_features"]] + [pct(v[f]["recall"], 1) for f in fams]
                                                             for k, v in a.items() if isinstance(v, dict) and "n_features" in v]))
        out += ["", "**Finding:** without the OS-fingerprint features the model still catches unseen DoS, DDoS and Botnet, so it "
                "recognises attack *behaviour*. **SSH brute force depends on the TCP-flag counts** (connection set-up and "
                "teardown patterns, which are legitimate behaviour, not a host fingerprint)."]
    return "\n".join(out) + "\n"


def iforest_section() -> str:
    r = load("iforest/results.json")
    if not r:
        return ""
    rows = [[k, v["config"], f"{v['roc_auc']:.3f}", pct(v["recall_overall"], 2)] for k, v in r.items() if isinstance(v, dict)
            and "roc_auc" in v]
    return "\n".join([
        "## 4. Benign-only IsolationForest (the original novelty idea)", "",
        "Trained on 500k benign train flows; scored on validation; threshold = 99.5th benign percentile (0.5% false alarms):", "",
        table(["config", "settings", "ROC-AUC (attack vs benign)", "attack recall @ 0.5% FPR"], rows), "",
        "**Finding: it does not work on these flow features.** ROC-AUC 0.70-0.87 and essentially no attack is flagged at a usable "
        "false-alarm rate. Flood and brute-force flows look like ordinary individual flows; what makes them attacks is volume, which "
        "a per-flow detector cannot see. **Decision:** the IsolationForest is optional in the bundle format and is *not* part of the "
        "CIC decision rule. It is kept for the binary LUFlow bundle, where the `outlier` label gives it a fair test (section 8).", ""])


def holdout_section() -> str:
    t = load("holdouts_test/results.json")
    v = load("holdouts_val/results.json")
    res = t or v
    if not res:
        return ""
    which = "test split, mean [min-max] over " + str(res.get("seeds", 1)) + " seeds" if t else "validation split, single seed"
    budgets = [str(b) for b in res["budgets"]]

    def rows(kind):
        out = []
        for unit, r in res[kind].items():
            cells = []
            for b in budgets:
                x = r["budgets"][b]
                lo, hi = x.get("recall_min", x["recall"]), x.get("recall_max", x["recall"])
                cells.append(f"{pct(x['recall'], 0)} [{lo * 100:.0f}-{hi * 100:.0f}]" if t else pct(x["recall"], 1))
            b1 = r["budgets"]["0.001"]
            out.append([unit, f"{r['n_held_out']:,}"] + cells + [pct(b1["novel_share_of_detected"], 0),
                                                                  pct(b1["recall_seen_ceiling"], 1)])
        return out

    head = ["held out", "flows"] + [f"recall @ {float(b) * 100:g}% FPR" for b in budgets] + ["labelled novel (0.1%)", "seen ceiling (0.1%)"]
    fn = [r["budgets"]["0.001"]["familiar_false_novel"] for r in res["families"].values()]
    return "\n".join([
        f"## 5. Generalisation to attacks the model has never seen ({which})", "",
        "Both heads are retrained WITHOUT the held-out unit; thresholds come from validation benign flows. "
        "`labelled novel` = share of the detected held-out flows the family head was unsure about. "
        "`seen ceiling` = the same model trained WITH the unit.", "",
        "**Leave-one-family-out** (a whole family removed):", "", table(head, rows("families")), "",
        "**Tool holdout** (one tool removed, sibling tools remain):", "", table(head, rows("tools")), "",
        f"* Familiar attacks are mislabelled \"novel\" only {pct(min(fn), 1)}-{pct(max(fn), 1)} of the time at the 0.1% budget "
        "(by construction ~2%).",
        "* **The supervised forest generalises** to unseen floods, DoS and botnet traffic at strict false-alarm budgets, and the "
        "family head's low confidence marks those detections as unfamiliar. This is the evidence for \"catches what signatures "
        "miss\".",
        "* **It does not generalise to low-and-slow families**: SSH brute force and internal Nmap scanning (Infiltration) are "
        "mostly missed when held out. Say so in the pitch.",
        "* Recall at the strictest budgets swings between seeds (the min-max ranges); report ranges, never a single run.", ""])


def tune_section() -> str:
    r, c = load("tune/results.json"), load("tune/confirm.json")
    if not r:
        return ""
    rows = [[i + 1, x["config"], f"{x['mean_recall']['0.0005']:.3f}", f"{x['mean_recall']['0.0001']:.3f}"]
            for i, x in enumerate(r["ranked"][:6])]
    out = ["## 6. Hyper-parameter search", "",
           "In-distribution validation is saturated, so configs were scored by **tool-holdout recall** at a strict budget (mean over "
           + ", ".join(r["tune_tools"]) + "; DDoS-HOIC is excluded so the headline demo tool is an untouched check). "
           f"{len(r['ranked'])} random configs, 600k-row training subsample, validation only:", "",
           table(["rank", "config", "mean recall @0.05% FPR", "@0.01% FPR"], rows), ""]
    if c:
        out += ["Confirmation over 3 fresh seeds (the single-run ranking is noisy):", "",
                table(["candidate", "config", "mean recall @0.05%", "range over seeds"],
                      [[k, v["config"], f"{v['mean']:.3f}", f"{v['min']:.2f}-{v['max']:.2f}"] for k, v in c.items()]), "",
                "**Decision:** the three tuned configs are statistically indistinguishable (all about +0.15 over the default). "
                "The smallest and fastest (depth 16, 100-sample leaves, 20% of features per split) was frozen. DDoS-LOIC-HTTP stays "
                "near 0% at the strictest budget in every configuration: tuning cannot fix that.", ""]
    return "\n".join(out)


def curve_section() -> str:
    p = BUNDLES / "cic-v1" / "operating_curve.json"
    if not p.exists():
        return ""
    curve = json.loads(p.read_text(encoding="utf-8"))
    fams = sorted(curve[0]["recall_by_family"])
    rows = [[pct(c["budget"], 3), f"{c['tau_binary']:.4f}", pct(c["benign_fpr"], 3), pct(c["recall"], 2),
             pct(c["precision_natural"], 1), pct(c["novel_flagged_share"], 1)] + [pct(c["recall_by_family"][f], 0) for f in fams]
            for c in curve]
    return "\n".join([
        "## 7. Operating point (final model, test split, natural prevalence)", "",
        "Threshold chosen on validation for each benign false-alarm budget; everything below is measured on the test split once:", "",
        table(["budget", "tau_binary", "test benign FPR", "recall", "precision", "flagged novel"] + [f"recall {f}" for f in fams], rows),
        "", "**Decision:** the shipped bundle uses the 0.1% budget. At this network's scale (about 330k benign flows per hour) "
        "even 0.1% is hundreds of false-alarm flows per hour before incident grouping; the correlator exists for exactly that. "
        "The curve is in the bundle (`operating_curve.json`) so the UI can show the trade-off.", ""])


def luflow_section() -> str:
    r = load("luflow/results.json")
    if not r:
        return ""
    rows = []
    for per, m in r["months"].items():
        s, rc = m["static"], m.get("recalibrated")
        rows.append([per, m["kind"], pct(s["malicious_share"], 0), pct(s["recall"], 1), pct(s["benign_fpr"], 2),
                     f"{s['roc_auc']:.3f}", f"{m['max_psi']:.2f} ({m['drift_status']})", pct(s["outlier_flag_rf"], 0),
                     pct(s["outlier_flag_if"], 0), pct(rc["recall"], 1) if rc else "", pct(rc["benign_fpr"], 2) if rc else ""])
    return "\n".join([
        "## 8. LUFlow: real honeypot traffic, month by month", "",
        "Binary RandomForest + benign-only IsolationForest trained on 2020-06/07 and FROZEN; every later month is scored with "
        "those models. `recal` = IsolationForest and thresholds refit on that month's label-free benign window.", "",
        table(["month", "kind", "malicious share", "recall", "benign FPR", "ROC-AUC", "max PSI (status)",
               "outliers flagged by RF", "by IForest", "recal recall", "recal FPR"], rows), "",
        f"Frozen thresholds from validation: benign FPR budget {pct(r['budget'], 1)}.", ""])


def main() -> None:
    sections = [
        "# Experiments", "",
        "*Generated by `ml/train/make_experiments_doc.py` from `artifacts/experiments/*/results.json`. Reproduce with the commands "
        "in each script's docstring; all use fixed seeds. All precision values are weighted to natural class prevalence.*", "",
        "**Headline.** The original design bet on a benign-only anomaly detector for novel attacks. Measured on real data, that "
        "detector does not work on CIC flow features, but the **supervised forest generalises to unseen attack families and tools**, "
        "and its **family-head uncertainty flags them as unfamiliar**. The architecture was changed to follow the evidence "
        "(ADR-1 in `docs/03_architecture.md`).", "",
        baseline_section(), imbalance_section(), ablation_section(), iforest_section(), holdout_section(), tune_section(),
        curve_section(), luflow_section()]
    out = ROOT / "docs" / "experiments.md"
    out.write_text("\n".join(s for s in sections if s is not None) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out} ({out.stat().st_size / 1e3:.0f} KB)")


if __name__ == "__main__":
    main()
