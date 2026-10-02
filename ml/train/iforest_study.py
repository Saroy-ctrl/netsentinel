"""M2-06: the IsolationForest, trained on BENIGN train flows only. Which configuration separates attacks best?

    python -m ml.train.iforest_study

An IsolationForest never sees an attack: it learns what normal looks like and scores how easily a flow is isolated.
Higher anomaly score = stranger. We compare a few configurations on VALIDATION: ROC-AUC (attack vs benign) and
recall at a 0.5% benign false-alarm rate (= the 99.5th percentile of benign validation scores, the planned
`tau_anomaly`), overall and per attack tool. Writes artifacts/experiments/iforest/results.json.
"""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

from ml.evaluate import metrics as M
from ml.train.baseline import per_tool_recall
from ml.train.common import SEED, dump_json, fit_transformer, is_attack, load_split, out_dir, timed

BENIGN_TRAIN = 500_000
CONFIGS = {
    "n100_s256": {"n_estimators": 100, "max_samples": 256},
    "n300_s256": {"n_estimators": 300, "max_samples": 256},
    "n200_s2048": {"n_estimators": 200, "max_samples": 2048},
    "n200_s8192": {"n_estimators": 200, "max_samples": 8192},
    "n200_s2048_f05": {"n_estimators": 200, "max_samples": 2048, "max_features": 0.5},
    "n200_s256_f03": {"n_estimators": 200, "max_samples": 256, "max_features": 0.3},
}


def main() -> None:
    train, val = load_split("cic", "train"), load_split("cic", "val")
    tr = fit_transformer("cic", train)
    benign_train = train[~is_attack(train, "cic")].sample(BENIGN_TRAIN, random_state=SEED)
    Xb = tr.transform(benign_train)
    Xv, yv, tools = tr.transform(val), is_attack(val, "cic"), val["tool"].to_numpy()
    benign_val = ~yv & (tools == "BENIGN")
    print(f"IF train {Xb.shape} benign | val {Xv.shape}, benign {int(benign_val.sum()):,}", flush=True)

    results = {}
    for name, kw in CONFIGS.items():
        with timed(name):
            iso = IsolationForest(random_state=SEED, n_jobs=-1, **kw).fit(Xb)
            s = -iso.score_samples(Xv)
        thr = np.quantile(s[benign_val], 0.995)
        flagged = s > thr
        pt = per_tool_recall(tools, yv, flagged)
        results[name] = {"config": kw, "roc_auc": float(roc_auc_score(yv, s)),
                         "benign_flag_rate": float(flagged[benign_val].mean()),
                         "recall_overall": float(flagged[yv].mean()),
                         "per_tool_recall_at_p99.5": pt}
        print(f"  {name:16s} AUC={results[name]['roc_auc']:.4f} recall@p99.5={results[name]['recall_overall']:.4f}",
              flush=True)
        for t, r in pt.items():
            if r["n"] >= 1000:
                print(f"      {t:36s} n={r['n']:>7,} recall={r['recall']:.3f}", flush=True)
    best = max(results, key=lambda k: results[k]["roc_auc"])
    results["best_by_auc"] = best
    dump_json(out_dir("iforest") / "results.json", results)
    print("best by ROC-AUC:", best)
    _ = M  # (kept for parity with other studies)


if __name__ == "__main__":
    main()
