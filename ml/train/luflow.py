"""M2-11: LUFlow = real honeypot traffic. Drift month by month, outlier capture, label-free recalibration, bundles.

    python -m ml.train.luflow                     # study + bundles netsentinel luflow-v1 and luflow-recal
    python -m ml.train.luflow --no-bundles

Binary only (benign vs malicious; `outlier` is never a training label). Models: RandomForest (p_malicious) and a benign-only
IsolationForest (novelty). Trained on the two earliest months, thresholds chosen on their validation block (benign FPR
budget for the RF, 99.5th benign percentile for the IForest), then every LATER month is scored with those frozen models:
  * recall / benign FPR / ROC-AUC on that month (natural prevalence weights), and max PSI vs the training distribution
  * how many `outlier` flows (abnormal but unexplained) the RF flags vs the IForest flags
  * recalibration: refit ONLY the IForest and re-pick BOTH thresholds from that month's recal window (benign flows from the
    first 20% of the month = "recent known-good traffic", no attack labels needed) and re-score the same month
Writes artifacts/experiments/luflow/results.json and (unless --no-bundles) artifacts/bundles/luflow-v1, luflow-recal.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import roc_auc_score

from ml.data.working_set import load
from ml.evaluate import metrics as M
from ml.evaluate.weights import luflow_weights
from ml.train.common import CONTRACTS, SEED, SPECS, dump_json, fit_transformer, out_dir, timed
from nscore.bundle.packager import build_bundle
from nscore.contracts.schemas import EvaluationReport, ExternalEvalResult
from nscore.drift import psi as D

BUDGET = 0.005
TAU_ANOMALY_PCT = 99.5
IF_TRAIN = 500_000
EARLY = ("2020-06", "2020-07")


def label(df: pd.DataFrame) -> np.ndarray:
    return (df["family"] == "Malicious").to_numpy()


def fit_if(X: np.ndarray, seed: int = SEED) -> IsolationForest:
    return IsolationForest(n_estimators=200, max_samples=8192, random_state=seed, n_jobs=-1).fit(X)


def thresholds(rf, iso, X_benign: np.ndarray, budget: float) -> tuple[float, float, np.ndarray]:
    """tau_binary for the benign FPR budget; tau_anomaly = score at the 99.5th benign percentile (sorted scores returned)."""
    p = rf.predict_proba(X_benign)[:, 1]
    t_b = M.threshold_for_fpr(np.zeros(len(p), int), p, budget)
    scores = np.sort(-iso.score_samples(X_benign))
    return float(t_b), float(np.quantile(scores, TAU_ANOMALY_PCT / 100)), scores


def score_month(rf, iso, X, df, w, t_b: float, t_a: float) -> dict:
    y = label(df)
    p = rf.predict_proba(X)[:, 1]
    a = -iso.score_samples(X)
    benign, outlier = (df["family"] == "BENIGN").to_numpy(), (df["family"] == "Outlier").to_numpy()
    lab = ~outlier  # `outlier` flows are unexplained, not benign: they must not count as negatives (that inflated FPR to 15-28%)
    rep = M.binary_report(y[lab], p[lab], t_b, w[lab])
    return {"n": int(len(df)), "recall": rep["recall"], "benign_fpr": rep["fpr"], "precision_natural": rep["precision"],
            "roc_auc": rep["roc_auc"], "malicious_share": float(y.mean()),
            "outlier_flag_rf": float((p[outlier] >= t_b).mean()) if outlier.any() else None,
            "outlier_flag_if": float((a[outlier] >= t_a).mean()) if outlier.any() else None,
            "benign_flag_if": float((a[benign] >= t_a).mean()), "if_roc_auc_malicious": float(roc_auc_score(y[lab], a[lab]))}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-bundles", action="store_true")
    ap.add_argument("--budget", type=float, default=BUDGET)
    a = ap.parse_args()

    train, val, test, recal = (load("luflow", s) for s in ("train", "val", "test", "recal"))
    tr = fit_transformer("luflow", train)
    Xtr = tr.transform(train)
    ytr = label(train)
    with timed("rf_binary"):
        rf = RandomForestClassifier(n_estimators=100, min_samples_leaf=5, class_weight="balanced_subsample",
                                    n_jobs=-1, random_state=SEED).fit(Xtr, ytr)
    benign_tr = Xtr[~ytr]
    with timed("iforest (benign only)"):
        iso = fit_if(benign_tr[np.random.default_rng(SEED).choice(len(benign_tr), min(IF_TRAIN, len(benign_tr)),
                                                                   replace=False)])
    Xv = tr.transform(val)
    benign_v = (val["family"] == "BENIGN").to_numpy()
    t_b, t_a, sorted_scores = thresholds(rf, iso, Xv[benign_v], a.budget)
    print(f"static thresholds from validation: tau_binary={t_b:.4f}  tau_anomaly(score)={t_a:.4f}", flush=True)
    ref = D.build_reference(Xtr, tr.feature_names)  # study: month-by-month PSI of all traffic (docs/experiments.md)
    ref_benign = D.build_reference(Xtr[~ytr], tr.feature_names)  # bundles: the API measures drift on benign traffic

    results = {"budget": a.budget, "tau_binary": t_b, "months": {}}
    periods = sorted(test["period"].unique())
    for per in periods:
        df = test[test["period"] == per]
        X = tr.transform(df)
        w = luflow_weights(df, "test")
        row = {"kind": "same_period" if per in EARLY else "later", "static": score_month(rf, iso, X, df, w, t_b, t_a)}
        psi_all = D.psi_all(ref, X, tr.feature_names)
        row["max_psi"] = float(max(psi_all.values()))
        row["worst_feature"] = max(psi_all, key=psi_all.get)
        row["drift_status"] = D.status(row["max_psi"]).value
        if per not in EARLY:
            rc = recal[recal["period"] == per]
            Xrc = tr.transform(rc)
            iso_r = fit_if(Xrc[np.random.default_rng(SEED).choice(len(Xrc), min(IF_TRAIN, len(Xrc)), replace=False)])
            t_b2, t_a2, _ = thresholds(rf, iso_r, Xrc, a.budget)
            row["recalibrated"] = score_month(rf, iso_r, X, df, w, t_b2, t_a2)
            row["tau_binary_recal"] = t_b2
        results["months"][per] = row
        s, r = row["static"], row.get("recalibrated")
        print(f"  {per} [{row['kind']:11s}] static: recall={s['recall']:.3f} fpr={s['benign_fpr']:.4f} auc={s['roc_auc']:.3f} "
              f"| outliers flagged rf={s['outlier_flag_rf']:.2f} if={s['outlier_flag_if']:.2f} | PSI max={row['max_psi']:.2f} "
              f"({row['drift_status']})" + (f" | recal: recall={r['recall']:.3f} fpr={r['benign_fpr']:.4f}" if r else ""),
              flush=True)
    dump_json(out_dir("luflow") / "results.json", results)
    if a.no_bundles:
        return

    # ---------------------------------------------------------------- bundles
    base = json.loads((CONTRACTS / "baselines" / "luflow.json").read_text(encoding="utf-8"))
    external = []
    for per, row in results["months"].items():
        if row["kind"] == "same_period":
            continue
        for proto, key, notes in (("real_world_temporal", "static", "frozen models + thresholds from the first two months"),
                                  ("real_world_recalibrated", "recalibrated",
                                   "IsolationForest + thresholds refit on a label-free recent benign window")):
            s = row[key]
            external.append(ExternalEvalResult(
                dataset="LUFlow", protocol=proto, period=per, binary_recall=s["recall"], benign_fpr=s["benign_fpr"],
                roc_auc=s["roc_auc"], novel_recall=s["outlier_flag_if"], max_psi=row["max_psi"], notes=notes))

    def package(name: str, rf_, iso_, t_b_, t_a_, scores_, X_ref, note: str) -> None:
        report = EvaluationReport(
            model_version=name, split_strategy="LUFlow: first two months 70/15/15 time-blocked; later months = drift tests",
            labels=[], per_class=[], confusion_matrix=[], macro_f1=0.0, binary_roc_auc=float(np.nanmean(
                [r["static"]["roc_auc"] for r in results["months"].values()])), binary_pr_auc=0.0,
            benign_fpr=a.budget, external=external,
            limitations=["Binary only: LUFlow has no attack families. Labels come from threat-intelligence feeds that can "
                         "lag real attacks; `outlier` is not a class. 8 sampled days per month.", note])
        build_bundle(
            Path("artifacts/bundles") / name, version=name, spec_path=SPECS["luflow"], transformer=tr, rf_binary=rf_,
            iforest=iso_, benign_val_scores=scores_,
            thresholds={"tau_binary": t_b_, "tau_family": 0.0, "tau_anomaly": TAU_ANOMALY_PCT, "operating_fpr": a.budget},
            drift_reference=ref_benign, baseline_stats=base, dataset="LUFlow (Lancaster University honeypots 2020-21)",
            split_strategy=report.split_strategy, metrics_summary={"budget": a.budget, "tau_binary": float(t_b_)},
            evaluation_report=json.loads(report.model_dump_json()),
            tags={"role": note, "recalibrated": str("recal" in name).lower()}, overwrite=True)
        print("wrote", Path("artifacts/bundles") / name)

    # tau_anomaly in the bundle is a PERCENTILE of the bundled benign scores (engine contract)
    package("luflow-v1", rf, iso, t_b, t_a, sorted_scores, Xtr, "trained on 2020-06/07, thresholds frozen")
    last = periods[-1]
    rc = recal[recal["period"] == last]
    Xrc = tr.transform(rc)
    iso_r = fit_if(Xrc[np.random.default_rng(SEED).choice(len(Xrc), min(IF_TRAIN, len(Xrc)), replace=False)])
    t_b2, t_a2, sc2 = thresholds(rf, iso_r, Xrc, a.budget)
    package("luflow-recal", rf, iso_r, t_b2, t_a2, sc2, Xrc,
            f"same RandomForest; IsolationForest + thresholds refit on the {last} recal window")


if __name__ == "__main__":
    main()
