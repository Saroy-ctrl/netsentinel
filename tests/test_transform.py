import joblib
import numpy as np
import pandas as pd
import pytest

from nscore.features.transform import FeatureSpec, FlowTransformer, MissingFeaturesError

SPEC = FeatureSpec.from_dict({
    "version": "1", "schema": "t", "nan_policy": "median_train",
    "features": [
        {"name": "dur", "raw_name": "Dur", "dtype": "float32", "clip": [0.0, 1000.0], "log1p": True},
        {"name": "x", "raw_name": "X", "dtype": "float32", "clip": [-5.0, 5.0], "log1p": False},
        {"name": "flag", "raw_name": "Flag", "dtype": "float32", "clip": [0.0, 1.0], "log1p": False},
    ],
    "optional": [{"name": "dst_port", "reason": "r", "default": False}],
})


def _df(n=200, seed=0):
    rng = np.random.default_rng(seed)
    return pd.DataFrame({"dur": rng.exponential(50, n), "x": rng.normal(0, 3, n), "flag": rng.integers(0, 2, n),
                         "dst_port": rng.integers(0, 65535, n), "junk": 1})


def test_parity_batch_vs_records_and_key_order():
    df = _df()
    tr = FlowTransformer(SPEC).fit(df)
    a = tr.transform(df)
    recs = df.to_dict("records")
    b = tr.transform_records(recs)
    c = tr.transform_records([dict(reversed(list(r.items()))) for r in recs])  # different key order
    assert a.dtype == np.float32 and a.shape == (200, 3)
    assert np.array_equal(a, b) and np.array_equal(a, c)


def test_clip_log1p_inf_and_nan_policy():
    train = _df()
    tr = FlowTransformer(SPEC).fit(train)
    odd = pd.DataFrame({"dur": [np.inf, -3.0, np.nan, 1e9], "x": [np.nan, 99, -99, 0], "flag": [0, 1, 2, np.nan]})
    out = tr.transform(odd)
    assert np.isfinite(out).all()
    assert out[0, 0] == pytest.approx(np.log1p(tr.medians_[0]), rel=1e-5)  # inf -> NaN -> median
    assert out[1, 0] == 0.0 and out[3, 0] == pytest.approx(np.log1p(1000.0), rel=1e-5)  # clip then log1p
    assert out[1, 1] == 5.0 and out[2, 1] == -5.0
    assert out[3, 2] == pytest.approx(tr.medians_[2])


def test_medians_come_from_fit_data_only():
    train = _df(seed=1)
    tr = FlowTransformer(SPEC).fit(train)
    other = _df(seed=2)
    other["x"] += 100  # a different distribution must not change the fitted medians
    before = tr.medians_.copy()
    tr.transform(other)
    assert np.array_equal(before, tr.medians_)


def test_missing_features_named_and_extras_ignored():
    tr = FlowTransformer(SPEC).fit(_df())
    with pytest.raises(MissingFeaturesError) as e:
        tr.transform_records([{"dur": 1.0, "x": 2.0}])
    assert e.value.missing == ["flag"]
    tr.transform_records([{"dur": 1.0, "x": 2.0, "flag": 0, "extra": "ignored"}])


def test_raw_values_are_untouched_and_scaled_option():
    df = _df()
    tr = FlowTransformer(SPEC).fit(df)
    assert np.array_equal(tr.raw(df), df[["dur", "x", "flag"]].to_numpy(dtype=np.float64))
    z = tr.transform(df, scaled=True)
    assert np.allclose(z.mean(0), 0, atol=1e-3) and np.allclose(z.std(0), 1, atol=1e-3)


def test_optional_feature_and_pickle_roundtrip(tmp_path):
    df = _df()
    tr = FlowTransformer(SPEC, include_optional=("dst_port",)).fit(df)
    assert tr.feature_names == ["dur", "x", "flag", "dst_port"]
    with pytest.raises(ValueError):
        FlowTransformer(SPEC, include_optional=("nope",))
    joblib.dump(tr, tmp_path / "t.joblib")
    assert np.array_equal(joblib.load(tmp_path / "t.joblib").transform(df), tr.transform(df))


def test_unfitted_transform_raises():
    with pytest.raises(RuntimeError):
        FlowTransformer(SPEC).transform(_df())
