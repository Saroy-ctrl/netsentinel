import json

import numpy as np
import pandas as pd
import pytest

from nscore.contracts.schemas import DriftStatus
from nscore.drift import psi as p


def _ref(n=50_000, seed=0):
    rng = np.random.default_rng(seed)
    X = np.column_stack([rng.normal(0, 1, n), rng.lognormal(2, 1, n), rng.integers(0, 3, n).astype(float)])
    return X, p.build_reference(X, ["gauss", "lognorm", "discrete"])


def test_same_distribution_is_ok():
    _, ref = _ref()
    rng = np.random.default_rng(1)
    window = np.column_stack([rng.normal(0, 1, 2000), rng.lognormal(2, 1, 2000), rng.integers(0, 3, 2000)])
    out = p.psi_all(ref, window)
    assert max(out.values()) < p.WATCH_AT
    assert p.status(max(out.values())) is DriftStatus.OK


def test_shifts_are_detected_and_ordered():
    X, ref = _ref()
    rng = np.random.default_rng(2)
    small = p.psi(ref["features"]["gauss"], rng.normal(0.3, 1, 5000))
    big = p.psi(ref["features"]["gauss"], rng.normal(1.5, 1, 5000))
    spread = p.psi(ref["features"]["gauss"], rng.normal(0, 3, 5000))
    assert small < big and big > p.ALERT_AT and spread > p.WATCH_AT
    assert p.status(big) is DriftStatus.ALERT


def test_discrete_feature_and_category_collapse():
    _, ref = _ref()
    assert p.psi(ref["features"]["discrete"], np.zeros(3000)) > p.ALERT_AT  # every value falls in one category


def test_nan_inf_ignored_and_empty_rejected():
    _, ref = _ref()
    rng = np.random.default_rng(3)
    v = np.concatenate([rng.normal(0, 1, 3000), [np.nan, np.inf, -np.inf]])
    assert p.psi(ref["features"]["gauss"], v) < p.WATCH_AT
    with pytest.raises(ValueError):
        p.psi(ref["features"]["gauss"], np.array([np.nan]))


def test_reference_is_json_roundtrippable_and_dataframe_input():
    X, _ = _ref(n=5000)
    df = pd.DataFrame(X, columns=["a", "b", "c"])
    ref = p.build_reference(df, ["a", "b", "c"], bins=8)
    again = json.loads(json.dumps(ref))
    assert p.psi_all(again, df) == p.psi_all(ref, df)
    assert all(sum(f["expected"]) == pytest.approx(1.0) for f in ref["features"].values())
    assert max(p.psi_all(ref, df).values()) < 0.01  # reference data against itself


def test_constant_feature_cannot_drift_and_bad_shape_rejected():
    ref = p.build_reference(np.ones((100, 1)), ["k"])
    assert p.psi(ref["features"]["k"], np.full(50, 7.0)) == pytest.approx(0.0, abs=1e-9)
    with pytest.raises(ValueError):
        p.psi_all(ref, np.ones((10, 2)), ["k"])
