import numpy as np
import pandas as pd

from ml.data import spec_builder as sb


def _sample(n=5000, seed=0):
    rng = np.random.default_rng(seed)
    a = rng.lognormal(3, 2, n)
    return pd.DataFrame({
        "a": a,
        "a_copy": a * 2 + 1,                     # perfectly (rank-)correlated with a
        "b": rng.normal(0, 1, n),
        "const": np.zeros(n),
        "neg": rng.normal(-5, 1, n),
        "heavy": rng.pareto(1.2, n) * 10,        # non-negative, heavy tail
    })


def _spec(df):
    raw = {c: c.upper() for c in df}
    return sb.build_spec(df, raw_names=raw, preference_key=lambda c: list(df).index(c), dataset="t", schema="t",
                         metadata={"ip": "identifier"})


def test_constant_and_correlated_dropped_with_reasons():
    spec, _, pairs = _spec(_sample())
    names = {f["name"] for f in spec["features"]}
    assert names == {"a", "b", "neg", "heavy"}
    d = {x["name"]: x for x in spec["dropped"]}
    assert "constant" in d["const"]["reason"]
    assert d["a_copy"]["kept_partner"] == "a" and d["a_copy"]["rho"] > 0.99
    assert ((pairs.a == "a") & (pairs.b == "a_copy")).any()


def test_preference_order_decides_which_of_a_pair_survives():
    df = _sample()
    raw = {c: c for c in df}
    spec, *_ = sb.build_spec(df, raw_names=raw, preference_key=lambda c: 0 if c == "a_copy" else 1, dataset="t",
                             schema="t", metadata={})
    assert "a_copy" in {f["name"] for f in spec["features"]} and "a" not in {f["name"] for f in spec["features"]}


def test_clip_log1p_and_policy():
    spec, *_ = _spec(_sample())
    f = {x["name"]: x for x in spec["features"]}
    assert f["heavy"]["log1p"] is True and f["neg"]["log1p"] is False and f["b"]["log1p"] is False
    assert f["b"]["clip"][0] < 0 < f["b"]["clip"][1]
    assert spec["nan_policy"] == "median_train" and spec["sample"]["rows"] == 5000
    assert abs(f["neg"]["train_median"] + 5) < 0.2


def test_stats_use_only_given_frame_and_nans_are_counted():
    df = _sample()
    df.loc[:49, "b"] = np.nan
    spec, stats, _ = _spec(df)
    assert abs(stats.at["b", "nan_rate"] - 0.01) < 1e-9
    assert {x["name"]: x for x in spec["features"]}["b"]["nan_rate"] == 0.01
