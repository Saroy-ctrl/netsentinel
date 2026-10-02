import numpy as np
import pandas as pd

from ml.data import baseline_stats as b


def test_compute_and_describe():
    rng = np.random.default_rng(0)
    df = pd.DataFrame({"iat": rng.lognormal(10, 0.5, 5000), "syn": np.zeros(5000), "pkts": rng.integers(1, 10, 5000)})
    s = b.compute(df, ["iat", "syn", "pkts"])
    assert s["syn"]["zero_share"] == 1.0 and s["syn"]["median"] == 0.0
    assert s["iat"]["p05"] < s["iat"]["median"] < s["iat"]["p95"]
    med = s["iat"]["median"]
    assert "4,000x below" in b.describe("flow_iat_mean", med / 4000, s["iat"])
    assert "x the benign median" in b.describe("flow_iat_mean", med * 50, s["iat"])
    assert "close to the benign median" in b.describe("flow_iat_mean", med * 1.1, s["iat"])
    assert "above the benign 95th percentile" in b.describe("syn_flag_count", 5.0, {**s["syn"], "p95": 1.0})
    assert "usually 0" in b.describe("syn_flag_count", 0.0, s["syn"])


def test_ratio_none_for_zero_median_and_nonfinite_ignored():
    assert b.ratio_to_median(5.0, {"median": 0.0}) is None
    assert b.ratio_to_median(10.0, {"median": 5.0}) == 2.0
    s = b.compute(pd.DataFrame({"x": [1.0, 2.0, 3.0, np.nan, np.inf]}), ["x"])
    assert s["x"]["median"] == 2.0
