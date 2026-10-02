"""The M2 training pipeline as functions: fit the two heads, pick the operating point, decide, evaluate.

Design (evidence: docs/experiments.md): a binary RandomForest decides ATTACK vs BENIGN; a family RandomForest trained on
attack flows only names the family; its confidence (max class probability) says whether the attack is FAMILIAR.
  p >= tau_binary and conf >= tau_family  -> KNOWN_ATTACK (family named)
  p >= tau_binary and conf <  tau_family  -> NOVEL_ANOMALY (unfamiliar attack; closest family reported)
  otherwise                               -> BENIGN
tau_binary comes from a benign false-alarm budget on VALIDATION; tau_family is the confidence below which only
`false_novel` (default 2%) of familiar validation attacks fall. Nothing here looks at the test split.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from ml.evaluate import metrics as M
from ml.train.common import SEED, is_attack
from nscore.features.transform import FlowTransformer

BIN_PARAMS = {"n_estimators": 100, "min_samples_leaf": 2, "class_weight": "balanced_subsample"}
FAM_PARAMS = {"n_estimators": 100, "min_samples_leaf": 2}


@dataclass
class Models:
    tr: FlowTransformer
    rf_bin: RandomForestClassifier
    rf_fam: RandomForestClassifier | None
    params: dict = field(default_factory=dict)


def fit_models(train: pd.DataFrame, tr: FlowTransformer, *, bin_params: dict | None = None,
               fam_params: dict | None = None, exclude: np.ndarray | None = None) -> Models:
    """exclude: boolean mask of TRAIN rows to leave out of BOTH heads (leave-one-family/tool-out)."""
    keep = train if exclude is None else train[~exclude]
    bp, fp = {**BIN_PARAMS, **(bin_params or {})}, {**FAM_PARAMS, **(fam_params or {})}
    X, y = tr.transform(keep), is_attack(keep, "cic")
    rf_bin = RandomForestClassifier(n_jobs=-1, random_state=SEED, **bp).fit(X, y)
    rf_fam = RandomForestClassifier(n_jobs=-1, random_state=SEED, **fp).fit(X[y], keep["family"].to_numpy()[y])
    return Models(tr, rf_bin, rf_fam, {"binary": bp, "family": fp, "train_rows": int(len(keep))})


def scores(m: Models, X: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """p_attack, family confidence, family index (into m.rf_fam.classes_) for every row (confidence is for ALL rows)."""
    p = m.rf_bin.predict_proba(X)[:, 1]
    proba = m.rf_fam.predict_proba(X)
    return p, proba.max(axis=1), proba.argmax(axis=1)


def operating_point(p_val: np.ndarray, conf_val: np.ndarray, benign_val: np.ndarray, familiar_attack_val: np.ndarray,
                    budget: float, false_novel: float = 0.02) -> dict:
    """tau_binary from the benign false-alarm budget; tau_family from familiar attacks that tau_binary flags."""
    tau_b = M.threshold_for_fpr(np.zeros(int(benign_val.sum()), dtype=int), p_val[benign_val], budget)
    flagged_familiar = familiar_attack_val & (p_val >= tau_b)
    tau_f = float(np.quantile(conf_val[flagged_familiar], false_novel)) if flagged_familiar.any() else 0.0
    return {"tau_binary": float(tau_b), "tau_family": tau_f, "budget": budget, "false_novel": false_novel,
            "n_familiar_for_tau_family": int(flagged_familiar.sum())}


def decide(p: np.ndarray, conf: np.ndarray, tau: dict) -> tuple[np.ndarray, np.ndarray]:
    """-> (is_attack_flagged, is_novel). Novel is always a subset of flagged."""
    flagged = p >= tau["tau_binary"]
    return flagged, flagged & (conf < tau["tau_family"])
