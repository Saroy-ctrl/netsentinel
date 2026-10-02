"""M2-10: train the final CIC (2018) models and package them as hash-verified bundles.

    python -m ml.train.build_bundles                       # full bundle  -> artifacts/bundles/cic-v1
    python -m ml.train.build_bundles --holdout Botnet      # WITHOUT Botnet -> artifacts/bundles/cic-holdout-botnet
    options: --budget 0.001  --params tuned|baseline  --out artifacts/bundles  --rows N (smoke test)

What happens:
  1. fit transformer + both forests on the train sample (the family head on attack flows only)
  2. thresholds on VALIDATION: tau_binary for the benign false-alarm budget, tau_family so that only 2% of familiar
     validation attacks fall below it ("unfamiliar")
  3. ONE evaluation on the TEST split at natural prevalence -> EvaluationReport (+ confusion PNG, operating curve)
  4. drift reference (PSI) from the transformed train matrix, benign baselines, SHAP global importance
  5. package (nscore.bundle.packager), then reload it and check the reloaded engine reproduces the test numbers
`--holdout F` leaves family F out of training AND validation calibration, then reports on test as usual (F's flows
count as misses or novel detections): this is the "never seen a botnet" demo model.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from ml.evaluate import metrics as M
from ml.evaluate.weights import cic_weights
from ml.train import pipeline as P
from ml.train.common import CONTRACTS, EXPERIMENTS, SEED, SPECS, fit_transformer, is_attack, load_split
from nscore.bundle.loader import load_bundle
from nscore.bundle.packager import build_bundle
from nscore.contracts.schemas import LoaoResult
from nscore.detection.engine import DetectionEngine
from nscore.detection.explain import Explainer
from nscore.drift.psi import build_reference

CURVE_BUDGETS = [0.0001, 0.0005, 0.001, 0.005, 0.01]
FALSE_NOVEL = 0.02


def predicted_labels(m: P.Models, X: np.ndarray, tau: dict) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    p, conf, idx = P.scores(m, X)
    flagged, novel = P.decide(p, conf, tau)
    fam = m.rf_fam.classes_[idx].astype(object)
    label = np.where(~flagged, "BENIGN", np.where(novel, "Unknown", fam))
    return p, conf, flagged, label


def operating_curve(m: P.Models, Xv, val, Xe, ev, w, holdout: str | None) -> list[dict]:
    pv, cv, _ = P.scores(m, Xv)
    pe, ce, _ = P.scores(m, Xe)
    benign_v = (val["tool"] == "BENIGN").to_numpy()
    familiar_v = (val["family"] != "BENIGN").to_numpy() & (val["family"] != (holdout or "")).to_numpy()
    y, fam = is_attack(ev, "cic"), ev["family"].to_numpy()
    out = []
    for b in CURVE_BUDGETS:
        tau = P.operating_point(pv, cv, benign_v, familiar_v, b, FALSE_NOVEL)
        flagged, novel = P.decide(pe, ce, tau)
        r = M.binary_report(y, flagged.astype(float), 0.5, w)
        out.append({"budget": b, "tau_binary": tau["tau_binary"], "tau_family": tau["tau_family"],
                    "benign_fpr": r["fpr"], "recall": r["recall"], "precision_natural": r["precision"],
                    "novel_flagged_share": float(novel[flagged].mean()) if flagged.any() else 0.0,
                    "recall_by_family": {f: float(flagged[fam == f].mean()) for f in sorted(set(fam))
                                         if f != "BENIGN"}})
    return out


def loao_results(split: str = "test") -> list[LoaoResult]:
    path = EXPERIMENTS / f"holdouts_{split}" / "results.json"
    if not path.exists():
        return []
    res = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for kind, key in (("family", "families"), ("tool", "tools")):
        for unit, r in res[key].items():
            b = r["budgets"]["0.001"]
            out.append(LoaoResult(held_out=unit, kind=kind, n_flows=r["n_held_out"], budget=0.001, recall=b["recall"],
                                  recall_min=b["recall_min"], recall_max=b["recall_max"],
                                  novel_share=b["novel_share_of_detected"], seen_recall=b["recall_seen_ceiling"],
                                  benign_fpr=b["benign_fpr"], seeds=r["seeds"]))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--holdout", help="family to leave out of training (demo bundle)")
    ap.add_argument("--budget", type=float, default=0.001)
    ap.add_argument("--params", choices=["tuned", "baseline"], default="tuned")
    ap.add_argument("--rows", type=int, help="train on a subsample (smoke test)")
    ap.add_argument("--out", type=Path, default=Path("artifacts/bundles"))
    a = ap.parse_args()
    name = "cic-holdout-" + a.holdout.lower() if a.holdout else "cic-v1"
    version = f"{name}-{pd.Timestamp.now('UTC').strftime('%Y%m%d')}"

    train, val, test = load_split("cic", "train"), load_split("cic", "val"), load_split("cic", "test")
    if a.rows:
        train = train.sample(a.rows, random_state=SEED).reset_index(drop=True)
    tr = fit_transformer("cic", train)
    exclude = (train["family"] == a.holdout).to_numpy() if a.holdout else None
    kw = {"bin_params": P.BASELINE_BIN_PARAMS} if a.params == "baseline" else {}
    print("params:", a.params, flush=True)
    m = P.fit_models(train, tr, exclude=exclude, **kw)
    Xv, Xt = tr.transform(val), tr.transform(test)

    pv, cv, _ = P.scores(m, Xv)
    benign_v = (val["tool"] == "BENIGN").to_numpy()
    familiar_v = (val["family"] != "BENIGN").to_numpy() & (val["family"] != (a.holdout or "")).to_numpy()
    tau = P.operating_point(pv, cv, benign_v, familiar_v, a.budget, FALSE_NOVEL)
    print("operating point:", tau, flush=True)

    w = cic_weights(test, "test")
    p_t, _, flagged, label = predicted_labels(m, Xt, tau)
    true = test["family"].to_numpy()
    limits = ["Test split = later time blocks of the SAME lab network and attack tools; see the leave-one-out table "
              "for generalisation. Attack families are 7.7% of flows; metrics are re-weighted to natural prevalence."]
    if a.holdout:
        limits.append(f"This bundle was trained WITHOUT {a.holdout}: its flows count as misses or novel detections.")
    report, extras = M.build_report(
        model_version=version, split_strategy="CSE-CIC-IDS2018 corrected: time-blocked per (day,family,tool) 70/15/15, "
        "60 s purge; test evaluated once", true=true, pred=label, p_attack=p_t, w=w, limitations=limits)
    report.loao = loao_results("test")
    binr = M.binary_report(is_attack(test, "cic"), flagged.astype(float), 0.5, w)
    print(f"TEST @budget {a.budget:.2%}: precision(natural)={binr['precision']:.4f} recall={binr['recall']:.4f} "
          f"fpr={binr['fpr']:.5f} macro-F1={report.macro_f1:.4f}", flush=True)
    for r in extras["per_class"]:
        print(f"   {r['family']:13s} support={r['support']:>9,} P={r['precision']:.3f} R={r['recall']:.3f} "
              f"F1={r['f1']:.3f} FPR={r['fpr']:.5f}  recall CI95 {r['recall_ci95'][0]:.3f}-{r['recall_ci95'][1]:.3f}")

    out = a.out / name
    tmp = out.parent / f".{name}-extras"
    tmp.mkdir(parents=True, exist_ok=True)
    M.save_confusion_png(report.confusion_matrix, [c.value for c in report.labels], tmp / "confusion_matrix.png",
                         f"{name}: test split (natural prevalence)")
    curve = operating_curve(m, Xv, val, Xt, test, w, a.holdout)
    (tmp / "operating_curve.json").write_text(json.dumps(curve, indent=1), encoding="utf-8")
    ex = Explainer(type("B", (), {"transformer": tr, "baseline_stats": json.loads(
        (CONTRACTS / "baselines" / "cic.json").read_text(encoding="utf-8")), "rf_binary": m.rf_bin})())
    atk_idx = np.flatnonzero(is_attack(val, "cic"))[:2000]
    imp = ex.global_importance(Xv[np.random.default_rng(SEED).choice(atk_idx, min(1000, len(atk_idx)), replace=False)])
    (tmp / "global_importance.json").write_text(json.dumps(imp, indent=1), encoding="utf-8")

    man = build_bundle(
        out, version=version, spec_path=SPECS["cic"], transformer=tr, rf_binary=m.rf_bin, rf_multiclass=m.rf_fam,
        thresholds={"tau_binary": tau["tau_binary"], "tau_family": tau["tau_family"], "operating_fpr": a.budget},
        drift_reference=build_reference(tr.transform(train.sample(min(len(train), 1_000_000), random_state=SEED)),
                                        tr.feature_names),
        baseline_stats=json.loads((CONTRACTS / "baselines" / "cic.json").read_text(encoding="utf-8")),
        dataset="CSE-CIC-IDS2018 (corrected, Liu/Engelen et al. 2022)", split_strategy=report.split_strategy,
        metrics_summary={"test_precision_natural": binr["precision"], "test_recall": binr["recall"],
                         "test_benign_fpr": binr["fpr"], "test_macro_f1": report.macro_f1,
                         "binary_roc_auc": report.binary_roc_auc, "binary_pr_auc": report.binary_pr_auc},
        evaluation_report=json.loads(report.model_dump_json()),
        tags={"held_out": a.holdout or "none", "params": json.dumps(m.params), "tau": json.dumps(tau),
              "train_rows": str(m.params["train_rows"])},
        extra_files={f.name: f for f in tmp.iterdir()}, overwrite=True)
    for f in tmp.iterdir():
        f.unlink()
    tmp.rmdir()

    # reload from disk and confirm the SERVING path reproduces the offline decision on a test sample
    b = load_bundle(f"local:{out}")
    samp = test.sample(20_000, random_state=SEED)
    det = DetectionEngine(b).detect(samp)
    _, _, ref_flag, _ = predicted_labels(m, tr.transform(samp), tau)
    same = float(np.mean([(v.value != "benign") == bool(f) for v, f in zip(det.verdict, ref_flag, strict=True)]))
    print(f"reloaded bundle {man.bundle_version}: serving path agrees with the training pipeline on {same:.4%} "
          "of 20k test flows")
    print("wrote", out)


if __name__ == "__main__":
    main()
