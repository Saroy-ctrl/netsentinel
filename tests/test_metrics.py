import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import confusion_matrix as sk_cm
from sklearn.metrics import precision_recall_fscore_support

from ml.evaluate import metrics as m


def test_binary_report_matches_hand_computation():
    y = np.array([1, 1, 1, 0, 0, 0, 0, 0])
    p = np.array([0.9, 0.8, 0.2, 0.7, 0.1, 0.1, 0.2, 0.3])
    r = m.binary_report(y, p, 0.5)
    assert (r["tp"], r["fn"], r["fp"], r["tn"]) == (2, 1, 1, 4)
    assert r["precision"] == pytest.approx(2 / 3) and r["recall"] == pytest.approx(2 / 3)
    assert r["fpr"] == pytest.approx(0.2)
    assert 0.5 < r["roc_auc"] <= 1 and "accuracy" not in r


def test_threshold_for_fpr_respects_budget_exactly():
    rng = np.random.default_rng(0)
    y = np.r_[np.zeros(10_000), np.ones(500)].astype(int)
    p = np.r_[rng.beta(2, 8, 10_000), rng.beta(8, 2, 500)]
    for budget in (0.001, 0.01, 0.05):
        t = m.threshold_for_fpr(y, p, budget)
        assert m.binary_report(y, p, t)["fpr"] <= budget
        assert m.binary_report(y, p, np.nextafter(t, -np.inf))["fpr"] > budget - 1e-3  # and not needlessly strict
    assert m.threshold_for_fpr(y, p, 0.0) > p[y == 0].max()


def test_family_report_matches_sklearn_and_orders_labels():
    true = np.array(["BENIGN"] * 6 + ["DoS"] * 3 + ["Botnet"] * 2 + ["WebAttack"])
    pred = np.array(["BENIGN"] * 5 + ["DoS"] + ["DoS", "DoS", "BENIGN"] + ["Botnet", "Unknown"] + ["BENIGN"])
    r = m.family_report(true, pred)
    assert r["labels"] == ["BENIGN", "DoS", "WebAttack", "Botnet", "Unknown"]  # canonical order, not alphabetical
    labels = r["labels"]
    assert (np.array(r["confusion_matrix"]) == sk_cm(true, pred, labels=labels)).all()
    p, rec, f, _ = precision_recall_fscore_support(true, pred, labels=labels, zero_division=0)
    for row, a, b, c in zip(r["per_class"], p, rec, f, strict=True):
        assert row["precision"] == pytest.approx(a) and row["recall"] == pytest.approx(b)
        assert row["f1"] == pytest.approx(c)
    web = next(x for x in r["per_class"] if x["family"] == "WebAttack")
    assert web["support"] == 1 and web["recall_ci95"][1] - web["recall_ci95"][0] > 0.5  # one flow -> huge uncertainty


def test_wilson_interval_edges():
    lo, hi = m.wilson(0, 10)
    assert lo == 0.0 and 0.2 < hi < 0.4
    lo, hi = m.wilson(10, 10)
    assert hi == 1.0 and 0.6 < lo < 0.8
    lo, hi = m.wilson(500, 1000)
    assert lo == pytest.approx(0.469, abs=0.01) and hi == pytest.approx(0.531, abs=0.01)
    assert m.wilson(0, 0) == (0.0, 1.0)


def test_build_report_is_a_valid_contract_and_flags_low_support(tmp_path):
    rng = np.random.default_rng(1)
    true = np.array(["BENIGN"] * 400 + ["DoS"] * 150 + ["WebAttack"] * 12)
    pred = true.copy()
    pred[:5] = "DoS"   # 5 benign false alarms
    pred[-3:] = "BENIGN"  # 3 missed web attacks
    p = np.where(pred != "BENIGN", 0.9, 0.1) + rng.normal(0, 0.01, len(true))
    rep, extra = m.build_report(model_version="t", split_strategy="s", true=true, pred=pred, p_attack=p)
    assert rep.benign_fpr == pytest.approx(5 / 400)
    assert any("WebAttack" in x and "only 12" in x for x in rep.limitations)
    assert {c.family.value for c in rep.per_class} == {"BENIGN", "DoS", "WebAttack"}
    m.save_confusion_png(rep.confusion_matrix, [c.value for c in rep.labels], tmp_path / "cm.png")
    assert (tmp_path / "cm.png").stat().st_size > 3000
    assert extra["binary"]["recall"] > 0.9


def test_weighting_restores_natural_precision_but_not_recall_or_fpr():
    # 10 attacks (all kept), 100 benign sampled from 1,000 (weight 10); 2 sampled benign are false alarms
    y = np.r_[np.ones(10), np.zeros(100)].astype(int)
    p = np.r_[np.full(8, 0.9), np.full(2, 0.1), np.full(2, 0.9), np.full(98, 0.1)]
    w = np.r_[np.ones(10), np.full(100, 10.0)]
    raw, nat = m.binary_report(y, p, 0.5), m.binary_report(y, p, 0.5, w)
    assert raw["precision"] == pytest.approx(8 / 10) and nat["precision"] == pytest.approx(8 / (8 + 20))
    assert raw["recall"] == nat["recall"] == pytest.approx(0.8)
    assert raw["fpr"] == nat["fpr"] == pytest.approx(0.02)
    assert nat["fp"] == 20 and nat["tn"] == 980 and nat["weighted"] is True and raw["weighted"] is False
    true = np.where(y == 1, "DoS", "BENIGN")
    pred = np.where(p >= 0.5, "DoS", "BENIGN")
    fam = m.family_report(true, pred, w=w)
    assert sum(fam["confusion_matrix"][0]) == 1000 and fam["per_class"][0]["support"] == 1000  # full-split counts
    assert fam["per_class"][0]["sample_support"] == 100
    assert fam["per_class"][1]["precision"] == pytest.approx(8 / 28)


def test_manifest_weights_from_counts():
    from ml.evaluate import weights as W

    counts = {"BENIGN / BENIGN": {"val": 1000}, "DoS / Hulk": {"val": 50}}
    samples = {"BENIGN / BENIGN": {"val": 100}, "DoS / Hulk": {"val": 50}}
    df = pd.DataFrame({"family": ["BENIGN", "DoS", "BENIGN"], "tool": ["BENIGN", "Hulk", "BENIGN"]})
    w = W._weights(df["family"] + " / " + df["tool"], counts, samples, "val")
    assert list(w) == [10.0, 1.0, 10.0]
    with pytest.raises(ValueError, match="missing"):
        W._weights(pd.Series(["Botnet / x"]), counts, samples, "val")
