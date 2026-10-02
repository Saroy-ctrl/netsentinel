"""M2-03: how should we handle class imbalance? Measured, not assumed.

    python -m ml.train.imbalance_study

Two questions, both answered on VALIDATION data only:
 A. Binary (attack vs benign): no weights vs class_weight="balanced_subsample" (the train sample is 29% attacks).
 B. Family head (attack flows only; 6 families, WebAttack has 194 training flows): no weights vs
    balanced_subsample vs SMOTE (train only; classes under SMOTE_TARGET oversampled to SMOTE_TARGET, then fit).
Metric of interest: per-family recall with a 95% interval and macro-F1 (accuracy is meaningless here).
SMOTE is applied to the TRAIN matrix only, after the split, never to validation: oversampling before splitting leaks
synthetic copies of test flows into training.
Writes artifacts/experiments/imbalance/results.json.
"""

from __future__ import annotations

import numpy as np
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score

from ml.evaluate import metrics as M
from ml.train.common import SEED, dump_json, fit_transformer, is_attack, load_split, out_dir, timed

BINARY_TRAIN = 1_000_000
SMOTE_TARGET = 5_000
TREES = 80


def rf(**kw) -> RandomForestClassifier:
    return RandomForestClassifier(n_estimators=TREES, min_samples_leaf=2, n_jobs=-1, random_state=SEED, **kw)


def main() -> None:
    train, val = load_split("cic", "train"), load_split("cic", "val")
    tr = fit_transformer("cic", train)
    results: dict = {"binary": {}, "family": {}}

    # ---------------------------------------------------------------- A. binary
    sub = train.sample(BINARY_TRAIN, random_state=SEED)
    Xs, ys, Xv, yv = tr.transform(sub), is_attack(sub, "cic"), tr.transform(val), is_attack(val, "cic")
    for name, kw in (("no_weights", {}), ("balanced_subsample", {"class_weight": "balanced_subsample"})):
        with timed(f"binary {name}"):
            p = rf(**kw).fit(Xs, ys).predict_proba(Xv)[:, 1]
        thr = M.threshold_for_fpr(yv, p, 0.001)
        r5 = M.binary_report(yv, p, 0.5)
        results["binary"][name] = {"at_0.5": r5, "at_fpr_0.1pct": M.binary_report(yv, p, thr)}
        print(name, {k: round(r5[k], 5) for k in ("precision", "recall", "fpr")}, flush=True)

    # ---------------------------------------------------------------- B. family head
    atk_tr, atk_va = train[is_attack(train, "cic")], val[is_attack(val, "cic")]
    Xa, ya = tr.transform(atk_tr), atk_tr["family"].to_numpy()
    Xav, yav = tr.transform(atk_va), atk_va["family"].to_numpy()
    classes = sorted(set(ya))
    print("family head train counts:", {c: int((ya == c).sum()) for c in classes}, flush=True)
    variants = {"no_weights": (Xa, ya, {}), "balanced_subsample": (Xa, ya, {"class_weight": "balanced_subsample"})}
    counts = {c: int((ya == c).sum()) for c in classes}
    strategy = {c: SMOTE_TARGET for c, n in counts.items() if n < SMOTE_TARGET}
    with timed("smote"):
        Xsm, ysm = SMOTE(sampling_strategy=strategy, k_neighbors=5, random_state=SEED).fit_resample(Xa, ya)
    variants["smote_to_5000"] = (Xsm, ysm, {})
    for name, (X, y, kw) in variants.items():
        with timed(f"family {name} (n={len(X):,})"):
            m = rf(**kw).fit(X, y)
            pred = m.predict(Xav)
        rep = M.family_report(yav, pred)
        results["family"][name] = {
            "n_train": int(len(X)), "macro_f1": rep["macro_f1"],
            "per_class": {r["family"]: {"recall": r["recall"], "precision": r["precision"], "support": r["support"],
                                        "recall_ci95": r["recall_ci95"]} for r in rep["per_class"]},
            "macro_f1_sklearn": float(f1_score(yav, pred, average="macro")),
        }
        pc = {r["family"]: f"{r['recall']:.3f}" for r in rep["per_class"]}
        print(f"  {name:20s} macro-F1={rep['macro_f1']:.4f} recall {pc}", flush=True)
    results["family_train_counts"] = counts
    results["config"] = {"binary_train_rows": BINARY_TRAIN, "smote_target": SMOTE_TARGET, "trees": TREES}
    dump_json(out_dir("imbalance") / "results.json", results)


if __name__ == "__main__":
    np.random.seed(SEED)
    main()
