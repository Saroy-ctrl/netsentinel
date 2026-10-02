import numpy as np
import pandas as pd

from ml.data import split as base
from ml.data import split_luflow as sl


def _meta(seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for period, start in (("2020-06", "2020-06-01"), ("2020-07", "2020-07-01"), ("2020-09", "2020-09-01")):
        t0 = pd.Timestamp(start)
        for fam, n in (("BENIGN", 600), ("Malicious", 400), ("Outlier", 100)):
            for s in rng.uniform(0, 30 * 86400, n):
                rows.append((period, f"{period}-d", fam, fam.lower(), t0 + pd.Timedelta(seconds=float(s))))
    df = pd.DataFrame(rows, columns=["period", "day", "family", "tool", "ts"])
    df["row"] = np.arange(len(df), dtype=np.int32)
    return df


def test_early_months_get_train_val_test_later_months_get_test_and_recal_only():
    m = _meta()
    s = sl.assign_luflow(m)
    early = m.period.isin(sl.EARLY_PERIODS).to_numpy()
    assert {base.TRAIN, base.VAL, base.TEST} <= set(s[early])
    assert set(s[~early]) <= {base.TEST, sl.RECAL, base.PURGED}
    assert not (s[~early] == base.TRAIN).any()


def test_recal_is_benign_only_and_strictly_before_test():
    m = _meta()
    s = sl.assign_luflow(m)
    later = m[m.period == "2020-09"]
    sl_ = s[later.index]
    recal, test = later[sl_ == sl.RECAL], later[sl_ == base.TEST]
    assert (recal.family == "BENIGN").all() and len(recal) > 0 and len(test) > 0
    assert recal.ts.max() < test.ts.min()
    assert (test.ts.min() - recal.ts.max()).total_seconds() >= 2 * base.PURGE_S - 1
    assert set(test.family) == {"BENIGN", "Malicious", "Outlier"}  # test keeps every label


def test_sample_excludes_outliers_from_training_and_is_deterministic():
    m = _meta()
    s = sl.assign_luflow(m)
    a, b = sl.working_sample(m, s), sl.working_sample(m, s)
    assert (a == b).all()
    train_sample = a & (s == base.TRAIN)
    assert not (train_sample & (m.family == "Outlier").to_numpy()).any()
    assert (a & (s == base.TEST) & (m.family == "Outlier").to_numpy()).any()  # outliers stay in the eval sample
