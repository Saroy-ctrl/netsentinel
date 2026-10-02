"""M1-05 split tests on synthetic flows."""

import numpy as np
import pandas as pd

from ml.data import split as sp


def _meta(n_benign=2000, n_hoic=600, n_udp=100, seed=0):
    rng = np.random.default_rng(seed)
    t0 = pd.Timestamp("2018-02-21 12:00:00")
    def burst(fam, tool, lo, hi, n):
        return [("Wed", fam, tool, t0 + pd.Timedelta(seconds=float(s))) for s in rng.uniform(lo, hi, n)]

    # benign over 10 h, HOIC burst for 1 h late, LOIC-UDP burst for 30 min early (same family, different time)
    rows = burst("BENIGN", "BENIGN", 0, 36000, n_benign)
    rows += burst("DDoS", "DDoS-HOIC", 28800, 32400, n_hoic)
    rows += burst("DDoS", "DDoS-LOIC-UDP", 3600, 5400, n_udp)
    df = pd.DataFrame(rows, columns=["day", "family", "tool", "ts"])
    df["row"] = np.arange(len(df), dtype=np.int32)
    return df


def test_every_group_in_every_split_and_time_ordered():
    m = _meta()
    s = sp.assign_splits(m)
    for tool, g in m.groupby("tool"):
        sg = s[g.index]
        assert {sp.TRAIN, sp.VAL, sp.TEST} <= set(sg), tool  # tools in different time windows all reach test
        t = g["ts"]
        assert t[sg == sp.TRAIN].max() < t[sg == sp.VAL].min() <= t[sg == sp.VAL].max() < t[sg == sp.TEST].min()


def test_purge_gap_respected():
    m = _meta()
    s = sp.assign_splits(m)
    g = m[m.tool == "BENIGN"]
    sg = s[g.index]
    gap = (g["ts"][sg == sp.VAL].min() - g["ts"][sg == sp.TRAIN].max()).total_seconds()
    assert gap >= 2 * min(sp.PURGE_S, 0.02 * 36000) - 1  # both sides of the boundary are purged
    assert (sg == sp.PURGED).sum() > 0


def test_short_groups_not_purged_away():
    m = _meta(n_udp=30)
    s = sp.assign_splits(m)
    udp = s[m.tool == "DDoS-LOIC-UDP"]
    assert (udp != sp.PURGED).sum() >= 20


def test_deterministic_and_identical_timestamps_stay_together():
    m = _meta()
    m.loc[m.tool == "DDoS-HOIC", "ts"] = pd.Timestamp("2018-02-21 20:00:00")  # all equal
    a, b = sp.assign_splits(m), sp.assign_splits(m)
    assert (a == b).all()
    assert len(set(a[m.tool == "DDoS-HOIC"])) == 1  # one timestamp -> one side, never split mid-tie


def test_sample_caps_and_seed():
    m = _meta()
    s = sp.assign_splits(m)
    a = sp.working_sample(m, s, cap_per_tool=100, benign_train=300, benign_eval=50)
    b = sp.working_sample(m, s, cap_per_tool=100, benign_train=300, benign_eval=50)
    assert (a == b).all()
    train = (s == sp.TRAIN) & a
    assert (train & (m.tool == "DDoS-HOIC").to_numpy()).sum() == 100
    assert (train & (m.family == "BENIGN").to_numpy()).sum() == 300
    test_attack = (s == sp.TEST) & (m.family == "DDoS").to_numpy()
    assert (a[test_attack]).all()  # evaluation keeps every attack flow


def test_loao_and_tool_holdout_masks():
    m = _meta()
    s = sp.assign_splits(m)
    mask = sp.exclude_family(m, s, "DDoS")
    assert not (mask & (m.family == "DDoS").to_numpy()).any() and mask.sum() > 0
    assert not (sp.exclude_tool(m, s, "DDoS-HOIC") & (m.tool == "DDoS-HOIC").to_numpy()).any()
    assert (sp.exclude_tool(m, s, "DDoS-HOIC") & (m.tool == "DDoS-LOIC-UDP").to_numpy()).any()  # LOIC stays
