"""Drift math (M1-07): Population Stability Index against a reference built from TRAIN data.

    ref = build_reference(X_train, names)           # saved as drift_reference.json in the model bundle
    psi(ref["features"]["flow_duration"], values)   # one feature, one window
    psi_all(ref, X_window, names)                   # every feature -> {name: psi}
    status(max_psi)                                 # DriftStatus: ok < 0.10 <= watch < 0.25 <= alert

PSI = sum_b (actual_b - expected_b) * ln(actual_b / expected_b) over reference-quantile bins, with an epsilon floor
so empty bins stay finite. Edges come from the training quantiles, so "expected" is ~uniform for continuous features
and the statistic reacts to any shift in location, spread or shape. Constant features have a single bin and can
never drift; the feature spec already removes them.

Consumers: api drift monitor (M3-08, rolling window), M2 LUFlow study (PSI per month), docs/model_card drift section.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from nscore.contracts.schemas import DriftStatus

EPS = 1e-4
WATCH_AT = 0.10
ALERT_AT = 0.25


def _as_matrix(X, names: list[str]) -> np.ndarray:
    if isinstance(X, pd.DataFrame):
        X = X[names].to_numpy()
    X = np.asarray(X, dtype=np.float64)
    if X.ndim != 2 or X.shape[1] != len(names):
        raise ValueError(f"expected (n, {len(names)}) matrix, got {X.shape}")
    return X


def _bin_counts(edges: np.ndarray, values: np.ndarray) -> np.ndarray:
    return np.bincount(np.searchsorted(edges, values, side="right"), minlength=len(edges) + 1)


def build_reference(X, names: list[str], bins: int = 10) -> dict:
    """Quantile bin edges + expected proportions per feature. JSON-serialisable."""
    M = _as_matrix(X, names)
    feats = {}
    for j, name in enumerate(names):
        col = M[:, j]
        col = col[np.isfinite(col)]
        if len(col) == 0:
            raise ValueError(f"feature {name!r} has no finite values in the reference data")
        edges = np.unique(np.quantile(col, np.linspace(0, 1, bins + 1)[1:-1]))
        counts = _bin_counts(edges, col)
        feats[name] = {"edges": edges.tolist(), "expected": (counts / counts.sum()).tolist(), "n": int(len(col))}
    return {"bins": bins, "eps": EPS, "features": feats}


def psi(ref_feature: dict, values) -> float:
    v = np.asarray(values, dtype=np.float64).ravel()
    v = v[np.isfinite(v)]
    if len(v) == 0:
        raise ValueError("no finite values in the window")
    edges = np.asarray(ref_feature["edges"], dtype=np.float64)
    expected = np.maximum(np.asarray(ref_feature["expected"], dtype=np.float64), EPS)
    actual = np.maximum(_bin_counts(edges, v) / len(v), EPS)
    return float(np.sum((actual - expected) * np.log(actual / expected)))


def psi_all(ref: dict, X, names: list[str] | None = None) -> dict[str, float]:
    names = names or list(ref["features"])
    M = _as_matrix(X, names)
    return {n: psi(ref["features"][n], M[:, j]) for j, n in enumerate(names)}


def status(value: float) -> DriftStatus:
    if value >= ALERT_AT:
        return DriftStatus.ALERT
    if value >= WATCH_AT:
        return DriftStatus.WATCH
    return DriftStatus.OK
