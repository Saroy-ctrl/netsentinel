"""M2-02: baseline RandomForest (binary attack vs benign) on the 2018 train sample, evaluated on VALIDATION only.

    python -m ml.train.baseline                  # full train sample
    python -m ml.train.baseline --subsample 300000

Defaults are deliberately plain (no tuning): 100 trees, balanced_subsample class weights, min_samples_leaf 2.
Reports validation precision / recall / FPR / AUC at the default 0.5 threshold and at the threshold that meets a
1% benign-FPR budget (chosen on validation), a per-attack-tool recall table, and training time. The test split is
NOT touched here. Writes artifacts/experiments/baseline/{metrics.json, rf_binary.joblib}.
"""

from __future__ import annotations

import argparse

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from ml.evaluate import metrics as M
from ml.evaluate.weights import cic_weights
from ml.train.common import SEED, dump_json, fit_transformer, is_attack, load_split, out_dir, timed


def per_tool_recall(tools: np.ndarray, y: np.ndarray, flagged: np.ndarray) -> dict:
    out = {}
    for t in sorted(set(tools[y])):
        m = (tools == t) & y
        k = int(flagged[m].sum())
        lo, hi = M.wilson(k, int(m.sum()))
        out[t] = {"n": int(m.sum()), "recall": k / int(m.sum()), "ci95": [round(lo, 4), round(hi, 4)]}
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--subsample", type=int, help="train on a random subset (smoke test)")
    ap.add_argument("--trees", type=int, default=100)
    ap.add_argument("--eval-only", action="store_true", help="re-evaluate the saved model (no retraining)")
    a = ap.parse_args()

    with timed("load"):
        train, val = load_split("cic", "train"), load_split("cic", "val")
        if a.subsample:
            train = train.sample(a.subsample, random_state=SEED)
    with timed("fit transformer + transform"):
        tr = fit_transformer("cic", train)
        Xtr, Xva = tr.transform(train), tr.transform(val)
    ytr, yva = is_attack(train, "cic"), is_attack(val, "cic")
    print(f"train {Xtr.shape} attacks {ytr.mean():.1%} | val {Xva.shape} attacks {yva.mean():.1%}", flush=True)

    d = out_dir("baseline" if not a.subsample else "baseline_smoke")
    if a.eval_only:
        rf = joblib.load(d / "rf_binary.joblib")
    else:
        with timed("fit rf_binary"):
            rf = RandomForestClassifier(n_estimators=a.trees, min_samples_leaf=2, class_weight="balanced_subsample",
                                        n_jobs=-1, random_state=SEED).fit(Xtr, ytr)
    with timed("predict val"):
        p = rf.predict_proba(Xva)[:, 1]

    w = cic_weights(val, "val")  # natural-prevalence correction (benign was down-sampled in the val sample)
    t_fpr = M.threshold_for_fpr(yva, p, 0.01)
    res = {"n_train": int(len(Xtr)), "n_val": int(len(Xva)), "trees": a.trees,
           "note": "precision/F1/counts are weighted to the full validation split (natural prevalence)",
           "at_0.5": M.binary_report(yva, p, 0.5, w), "at_fpr_1pct": M.binary_report(yva, p, t_fpr, w),
           "sample_precision_at_0.5": M.binary_report(yva, p, 0.5)["precision"],
           "sample_precision_at_fpr_1pct": M.binary_report(yva, p, t_fpr)["precision"]}
    tools = val["tool"].to_numpy()
    res["per_tool_recall_at_0.5"] = per_tool_recall(tools, yva, p >= 0.5)
    res["per_tool_recall_at_fpr_1pct"] = per_tool_recall(tools, yva, p >= t_fpr)
    imp = sorted(zip(tr.feature_names, rf.feature_importances_, strict=True), key=lambda kv: -kv[1])[:12]
    res["top_importances"] = [(n, round(float(v), 4)) for n, v in imp]

    dump_json(d / "metrics.json", res)
    if not a.eval_only:
        joblib.dump(rf, d / "rf_binary.joblib", compress=3)
    for k in ("at_0.5", "at_fpr_1pct"):
        r = res[k]
        print(f"{k:12s} thr={r['threshold']:.4f} precision={r['precision']:.4f} recall={r['recall']:.4f} "
              f"fpr={r['fpr']:.5f} roc_auc={r['roc_auc']:.5f} pr_auc={r['pr_auc']:.5f}")
    print(f"precision on the raw (attack-heavy) sample: {res['sample_precision_at_0.5']:.4f} @0.5, "
          f"{res['sample_precision_at_fpr_1pct']:.4f} @FPR1% -> natural prevalence is what counts")
    print("\nrecall per attack tool @ FPR<=1% (95% CI):")
    for t, r in res["per_tool_recall_at_fpr_1pct"].items():
        print(f"  {t:48s} n={r['n']:>7,} recall={r['recall']:.4f} {r['ci95']}")
    print("\ntop features:", res["top_importances"][:8])


if __name__ == "__main__":
    main()
