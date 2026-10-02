"""Bundle format + detection engine, on tiny synthetic bundles (same code path as real bundles)."""

import importlib.util
import shutil
from pathlib import Path

import numpy as np
import pytest

from nscore.bundle.loader import BundleIntegrityError, load_bundle
from nscore.bundle.packager import build_bundle
from nscore.contracts.schemas import AttackFamily, ModelInfo, Verdict
from nscore.detection.engine import DetectionEngine

ROOT = Path(__file__).resolve().parents[1]
_s = importlib.util.spec_from_file_location("make_mock_bundle", ROOT / "scripts" / "make_mock_bundle.py")
mock = importlib.util.module_from_spec(_s)
_s.loader.exec_module(mock)


@pytest.fixture(scope="module")
def bundles(tmp_path_factory):
    root = tmp_path_factory.mktemp("bundles")
    return {s: mock.build(s, root) for s in ("cic", "luflow")}


def _records(bundle, n=400, seed=1):
    rng = np.random.default_rng(seed)
    df, *_ = mock.synthetic_frame(bundle.spec, rng)
    return df.head(n)


def test_roundtrip_model_info_and_optional_parts(bundles):
    cic, lu = load_bundle(f"local:{bundles['cic']}"), load_bundle(str(bundles["luflow"]))
    assert cic.family_head and cic.iforest is None and cic.benign_val_scores is None  # CIC: no IsolationForest
    assert not lu.family_head and lu.iforest is not None and len(lu.benign_val_scores) > 100
    assert cic.feature_schema == "cic" and len(cic.spec.names) == 46 and lu.feature_schema == "luflow"
    info = ModelInfo.model_validate(cic.model_info().model_dump(mode="json"))
    assert info.registry == "local" and set(info.thresholds) == {"tau_binary", "tau_family"}
    assert "tau_anomaly" in lu.model_info().thresholds and cic.manifest.tags["mock"] == "true"


def test_engine_family_confidence_path_marks_unfamiliar_attacks_novel(bundles):
    b = load_bundle(f"local:{bundles['cic']}")
    eng = DetectionEngine(b)
    det = eng.detect(_records(b).to_dict("records"))  # serving path: list of dicts
    assert len(det) == 400 and det.X.shape == (400, 46) and not eng.has_anomaly
    assert ((det.p_attack >= 0) & (det.p_attack <= 1)).all() and (det.anomaly_percentile == 0).all()
    kinds = set()
    for i, v in enumerate(det.verdict):
        kinds.add(v)
        if v is Verdict.KNOWN_ATTACK:
            assert det.p_attack[i] >= eng.tau_binary and det.family_confidence[i] >= eng.tau_family
            assert det.family[i] not in (AttackFamily.BENIGN, AttackFamily.UNKNOWN)
            assert det.family[i] is det.closest_family[i] and det.confidence[i] == det.p_attack[i]
            assert sum(det.family_probs[i].values()) == pytest.approx(1.0)
        elif v is Verdict.NOVEL_ANOMALY:
            assert det.p_attack[i] >= eng.tau_binary and det.family_confidence[i] < eng.tau_family
            assert det.family[i] is AttackFamily.UNKNOWN and det.closest_family[i] is not None
            assert det.confidence[i] == det.p_attack[i]  # we are as sure it is an attack as p says
        else:
            assert det.p_attack[i] < eng.tau_binary and det.family[i] is AttackFamily.BENIGN
            assert det.confidence[i] == 0 and det.closest_family[i] is None
    assert kinds == {Verdict.KNOWN_ATTACK, Verdict.NOVEL_ANOMALY, Verdict.BENIGN}
    again = eng.detect(_records(b))  # DataFrame path agrees (RF averages trees in parallel: tolerance)
    assert np.allclose(again.p_attack, det.p_attack, atol=1e-9) and again.verdict == det.verdict


def test_tau_family_controls_novelty(bundles):
    b = load_bundle(f"local:{bundles['cic']}")
    df = _records(b)
    strict, lax = DetectionEngine(b), DetectionEngine(b)
    strict.tau_family, lax.tau_family = 1.01, 0.0  # nothing is familiar enough / everything is familiar
    n_strict = sum(v is Verdict.NOVEL_ANOMALY for v in strict.detect(df).verdict)
    n_lax = sum(v is Verdict.NOVEL_ANOMALY for v in lax.detect(df).verdict)
    flagged = int((strict.p_attack(strict.transform(df)) >= strict.tau_binary).sum())
    assert n_lax == 0 and n_strict == flagged > 0


def test_binary_only_bundle_answers_malicious_and_uses_anomaly_path(bundles):
    b = load_bundle(f"local:{bundles['luflow']}")
    eng = DetectionEngine(b)
    det = eng.detect(_records(b))
    known = {f for f, v in zip(det.family, det.verdict, strict=True) if v is Verdict.KNOWN_ATTACK}
    assert known == {AttackFamily.MALICIOUS} and eng.has_anomaly
    assert (det.anomaly_percentile >= 0).all() and (det.anomaly_percentile <= 100).all()
    novel = [i for i, v in enumerate(det.verdict) if v is Verdict.NOVEL_ANOMALY]
    assert all(det.p_attack[i] < eng.tau_binary and det.anomaly_percentile[i] >= eng.tau_anomaly for i in novel)


def test_tampering_missing_and_extra_files_are_refused(bundles, tmp_path):
    def fresh():
        d = tmp_path / "b"
        shutil.rmtree(d, ignore_errors=True)
        shutil.copytree(bundles["cic"], d)
        return d

    d = fresh()
    (d / "thresholds.json").write_text('{"tau_binary": 0.01, "tau_family": 0, "operating_fpr": 0.5}')
    with pytest.raises(BundleIntegrityError, match="sha256 mismatch"):
        load_bundle(f"local:{d}")
    d = fresh()
    (d / "rf_binary.joblib").unlink()
    with pytest.raises(BundleIntegrityError, match="missing files"):
        load_bundle(f"local:{d}")
    d = fresh()
    (d / "sneaky.py").write_text("print(1)")
    with pytest.raises(BundleIntegrityError, match="unlisted"):
        load_bundle(f"local:{d}")
    d = fresh()
    (d / "manifest.json").unlink()
    with pytest.raises(BundleIntegrityError, match="no manifest"):
        load_bundle(f"local:{d}")


def test_packager_guards(bundles, tmp_path):
    b = load_bundle(f"local:{bundles['cic']}")
    lu = load_bundle(f"local:{bundles['luflow']}")
    common = dict(spec_path=bundles["cic"] / "feature_spec.json", transformer=b.transformer, rf_binary=b.rf_binary,
                  drift_reference=b.drift_reference, baseline_stats=b.baseline_stats, dataset="t",
                  split_strategy="t", metrics_summary={})
    with pytest.raises(FileExistsError):
        build_bundle(bundles["cic"], version="x", thresholds=b.thresholds, **common)
    with pytest.raises(ValueError, match="thresholds missing"):
        build_bundle(tmp_path / "x", version="x", thresholds={"tau_binary": 0.5}, **common)
    with pytest.raises(ValueError, match="both or neither"):
        build_bundle(tmp_path / "y", version="x", thresholds=b.thresholds, iforest=lu.iforest, **common)
    with pytest.raises(ValueError, match="needs thresholds"):
        build_bundle(tmp_path / "y2", version="x", thresholds=b.thresholds, iforest=lu.iforest,
                     benign_val_scores=lu.benign_val_scores, **common)
    with pytest.raises(ValueError, match="at least 100"):
        build_bundle(tmp_path / "y3", version="x", thresholds=lu.thresholds, iforest=lu.iforest,
                     benign_val_scores=np.arange(5), **common)
    other = bundles["luflow"] / "feature_spec.json"  # transformer fitted with the CIC spec, bundling the LUFlow spec
    with pytest.raises(ValueError, match="different feature spec"):
        build_bundle(tmp_path / "z", version="x", thresholds=b.thresholds, **{**common, "spec_path": other})


def test_ref_schemes():
    with pytest.raises(ValueError, match="bad azureml ref"):
        load_bundle("azureml:two words")
    with pytest.raises(ValueError, match="unknown bundle ref scheme"):
        load_bundle("s3:bucket/x")


def test_explainer_top_features_are_ranked_additive_and_carry_baselines(bundles):
    from nscore.detection.explain import Explainer

    b = load_bundle(f"local:{bundles['cic']}")
    det = DetectionEngine(b).detect(_records(b, n=60))
    assert det.raw.shape == det.X.shape
    ex = Explainer(b, fast_trees=10)
    sv = ex.shap_values(det.X[:20])
    # additivity: base value + sum(SHAP) reproduces the model's P(attack) for each flow
    base = ex._full.expected_value[ex._attack_idx]
    assert np.allclose(base + sv.sum(axis=1), det.p_attack[:20], atol=1e-6)
    top = ex.contributions(det.X[:5], det.raw[:5], k=5)
    assert len(top) == 5 and all(len(t) == 5 for t in top)
    for t in top:
        mags = [abs(c.shap_value) for c in t]
        assert mags == sorted(mags, reverse=True)
        assert all(c.baseline_median is not None and c.feature in b.transformer.feature_names for c in t)
    i = 0
    assert top[0][0].value == pytest.approx(det.raw[i, b.transformer.feature_names.index(top[0][0].feature)])
    fast = ex.contributions(det.X[:5], det.raw[:5], k=5, fast=True)
    assert len(fast) == 5 and len(ex.global_importance(det.X, fast=True)) == 46
