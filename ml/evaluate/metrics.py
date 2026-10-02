"""M2-02: evaluation harness. Every number in the model card, the dashboard and the deck comes from here.

  binary_report(y, p, thr)               precision / recall / F1 / FPR / ROC-AUC / PR-AUC for attack vs benign
  threshold_for_fpr(y, p, budget)        the lowest threshold whose benign FPR is <= budget (picked on VALIDATION)
  family_report(true, pred, ...)         one-vs-rest per-class P/R/F1/FPR/AUC, confusion matrix, macro-F1, Wilson CIs
  build_report(...)                      -> nscore.contracts.EvaluationReport (what the API/dashboard serve)
  save_confusion_png(...)                heatmap artifact (row-normalised, counts annotated)

Prevalence: our val/test samples keep every attack flow but only a fraction of benign flows, which inflates precision.
Pass `w` (ml/evaluate/weights.py: benign rows weighted by 1/sampling-fraction) and every count, precision, F1 and
the confusion matrix become estimates for the FULL split. Recall and FPR do not depend on the weights.

Honesty rules baked in: accuracy is never reported; FPR is first-class; per-class recall carries a 95% Wilson
interval and families with < 100 test flows are flagged in `limitations`; the test split is only evaluated
by the final scripts, never used to choose a threshold or hyper-parameter.
"""

from __future__ import annotations

import math
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from nscore.contracts.schemas import AttackFamily, EvaluationReport, PerClassMetrics

CANONICAL = ["BENIGN", "DoS", "DDoS", "BruteForce", "WebAttack", "Infiltration", "Botnet", "Rare", "Malicious",
             "Unknown"]
LOW_SUPPORT = 100


def _div(a: float, b: float) -> float:
    return float(a / b) if b else 0.0


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion (valid at k = 0 or k = n, unlike the normal approximation)."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def binary_report(y: np.ndarray, p: np.ndarray, thr: float, w: np.ndarray | None = None) -> dict:
    y = np.asarray(y).astype(bool)
    pred = np.asarray(p) >= thr
    weighted = w is not None and not np.all(np.asarray(w) == 1.0)
    w = np.ones(len(y)) if w is None else np.asarray(w, dtype=np.float64)
    tp, fp = float(w[pred & y].sum()), float(w[pred & ~y].sum())
    fn, tn = float(w[~pred & y].sum()), float(w[~pred & ~y].sum())
    n_att, n_ben = int(y.sum()), int((~y).sum())  # raw sample sizes, used for confidence intervals
    out = {"threshold": float(thr), "n": int(len(y)), "n_attack": n_att, "n_benign": n_ben, "weighted": weighted,
           "tp": round(tp), "fp": round(fp), "fn": round(fn), "tn": round(tn),
           "precision": _div(tp, tp + fp), "recall": _div(tp, tp + fn), "fpr": _div(fp, fp + tn)}
    out["f1"] = _div(2 * out["precision"] * out["recall"], out["precision"] + out["recall"])
    if y.any() and (~y).any():
        out["roc_auc"] = float(roc_auc_score(y, p, sample_weight=w))
        out["pr_auc"] = float(average_precision_score(y, p, sample_weight=w))
    else:
        out["roc_auc"] = out["pr_auc"] = float("nan")
    out["recall_ci95"] = wilson(int((pred & y).sum()), n_att)
    out["fpr_ci95"] = wilson(int((pred & ~y).sum()), n_ben)
    return out


def threshold_for_fpr(y: np.ndarray, p: np.ndarray, budget: float) -> float:
    """Smallest threshold t with FPR(t) <= budget, where a flow is flagged when p >= t. Uses benign scores only."""
    benign = np.sort(np.asarray(p)[~np.asarray(y).astype(bool)])
    if len(benign) == 0:
        raise ValueError("no benign flows to calibrate on")
    k = int(math.floor(budget * len(benign)))  # at most k benign flows may be flagged
    if k == 0:
        return float(np.nextafter(benign[-1], np.inf))
    return float(np.nextafter(benign[-k - 1], np.inf))  # strictly above the (k+1)-th largest benign score


def _order(labels) -> list[str]:
    seen = set(labels)
    return [c for c in CANONICAL if c in seen] + sorted(seen - set(CANONICAL))


def family_report(true, pred, proba: np.ndarray | None = None, classes: list[str] | None = None,
                  w: np.ndarray | None = None) -> dict:
    """true / pred: arrays of family names. proba (n, len(classes)): optional, enables per-class ROC-AUC."""
    true, pred = np.asarray(true).astype(str), np.asarray(pred).astype(str)
    labels = _order(set(true) | set(pred))
    idx = {c: i for i, c in enumerate(labels)}
    w = np.ones(len(true)) if w is None else np.asarray(w, dtype=np.float64)
    ti, pi = np.vectorize(idx.get)(true), np.vectorize(idx.get)(pred)
    cm = np.zeros((len(labels), len(labels)), dtype=np.float64)  # weighted counts = expected counts for the full split
    np.add.at(cm, (ti, pi), w)
    raw = np.zeros_like(cm)
    np.add.at(raw, (ti, pi), 1.0)  # sample counts, for intervals
    total = cm.sum()
    per = []
    for c in labels:
        i = idx[c]
        tp, fp = float(cm[i, i]), float(cm[:, i].sum() - cm[i, i])
        fn, tn = float(cm[i, :].sum() - cm[i, i]), float(total - cm[i, :].sum() - cm[:, i].sum() + cm[i, i])
        prec, rec = _div(tp, tp + fp), _div(tp, tp + fn)
        row = {"family": c, "precision": prec, "recall": rec, "f1": _div(2 * prec * rec, prec + rec),
               "fpr": _div(fp, fp + tn), "support": round(tp + fn),
               "recall_ci95": wilson(int(raw[i, i]), int(raw[i, :].sum())),
               "sample_support": int(raw[i, :].sum()), "roc_auc": None}
        if proba is not None and classes and c in classes and 0 < (true == c).sum() < len(true):
            row["roc_auc"] = float(roc_auc_score(true == c, proba[:, classes.index(c)], sample_weight=w))
        per.append(row)
    with_support = [r for r in per if r["support"] > 0]
    return {"labels": labels, "confusion_matrix": np.rint(cm).astype(np.int64).tolist(), "per_class": per,
            "macro_f1": float(np.mean([r["f1"] for r in with_support])) if with_support else 0.0}


def build_report(*, model_version: str, split_strategy: str, true, pred, p_attack: np.ndarray,
                 benign_fpr: float | None = None, proba: np.ndarray | None = None, classes: list[str] | None = None,
                 limitations: list[str] | None = None,
                 w: np.ndarray | None = None) -> tuple[EvaluationReport, dict]:
    """Returns (contract report, extras with CIs / binary details that the contract has no field for)."""
    true = np.asarray(true).astype(str)
    fam = family_report(true, pred, proba, classes, w)
    y = true != "BENIGN"
    bin_ = binary_report(y, p_attack, 0.5, w)
    benign_pred_attack = (np.asarray(pred).astype(str) != "BENIGN") & ~y
    fpr = float(benign_pred_attack.sum() / max((~y).sum(), 1)) if benign_fpr is None else benign_fpr
    lims = list(limitations or [])
    for r in fam["per_class"]:
        if 0 < r["sample_support"] < LOW_SUPPORT:
            lims.append(f"{r['family']}: only {r['sample_support']} test flows, so its metrics are unreliable "
                        f"(recall 95% CI {r['recall_ci95'][0]:.2f}-{r['recall_ci95'][1]:.2f})")
    known = {a.value for a in AttackFamily}
    per = [PerClassMetrics(family=AttackFamily(r["family"]), precision=r["precision"], recall=r["recall"], f1=r["f1"],
                           fpr=r["fpr"], support=r["support"], roc_auc=r["roc_auc"])
           for r in fam["per_class"] if r["family"] in known]
    report = EvaluationReport(
        model_version=model_version, split_strategy=split_strategy,
        labels=[AttackFamily(c) for c in fam["labels"] if c in known], per_class=per,
        confusion_matrix=fam["confusion_matrix"], macro_f1=fam["macro_f1"],
        binary_roc_auc=bin_["roc_auc"], binary_pr_auc=bin_["pr_auc"], benign_fpr=fpr, limitations=lims)
    return report, {"binary": bin_, "per_class": fam["per_class"]}


def save_confusion_png(cm, labels: list[str], path: str | Path, title: str = "Confusion matrix") -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    cm = np.asarray(cm)
    norm = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
    fig, ax = plt.subplots(figsize=(1.0 + 0.9 * len(labels), 0.8 + 0.8 * len(labels)))
    im = ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(labels)), labels, rotation=40, ha="right")
    ax.set_yticks(range(len(labels)), labels)
    ax.set_xlabel("predicted")
    ax.set_ylabel("true")
    ax.set_title(title)
    for i in range(len(labels)):
        for j in range(len(labels)):
            if cm[i, j]:
                ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", fontsize=7,
                        color="white" if norm[i, j] > 0.5 else "black")
    fig.colorbar(im, ax=ax, fraction=0.046, label="share of true class")
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
