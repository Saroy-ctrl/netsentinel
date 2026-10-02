"""Bundle format + detection engine, on tiny synthetic bundles (same code path as real bundles)."""

import importlib.util
import shutil
from pathlib import Path

import numpy as np
import pandas as pd
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


def _records(bundle, n=300, seed=1):
    rng = np.random.default_rng(seed)
    df, *_ = mock.synthetic_frame(bundle.spec, rng)
    return df.head(n)


def test_roundtrip_model_info_and_head(bundles):
    cic, lu = load_bundle(f"local:{bundles['cic']}"), load_bundle(str(bundles["luflow"]))
    assert cic.family_head and cic.feature_schema == "cic" and len(cic.spec.names) == 46
    assert not lu.family_head and lu.feature_schema == "luflow"
    info = ModelInfo.model_validate(cic.model_info().model_dump(mode="json"))
    assert info.registry == "local" and info.thresholds["tau_binary"] == 0.5 and info.family_head is True
    assert cic.manifest.tags["mock"] == "true" and cic.manifest.tags["feature_schema"] == "cic"


def test_engine_decisions_are_consistent(bundles):
    b = load_bundle(f"local:{bundles['cic']}")
    eng = DetectionEngine(b)
    det = eng.detect(_records(b).to_dict("records"))  # serving path: list of dicts
    assert len(det) == 300 and det.X.shape == (300, 46)
    assert ((det.p_attack >= 0) & (det.p_attack <= 1)).all()
    assert ((det.anomaly_percentile >= 0) & (det.anomaly_percentile <= 100)).all()
    for i, v in enumerate(det.verdict):
        if v is Verdict.KNOWN_ATTACK:
            assert det.p_attack[i] >= eng.tau_binary
            assert det.family[i] not in (AttackFamily.BENIGN, AttackFamily.UNKNOWN)
            assert sum(det.family_probs[i].values()) == pytest.approx(1.0) and det.confidence[i] == det.p_attack[i]
        elif v is Verdict.NOVEL_ANOMALY:
            assert det.p_attack[i] < eng.tau_binary and det.family[i] is AttackFamily.UNKNOWN
            assert det.confidence[i] >= 0.5
        else:
            assert det.family[i] is AttackFamily.BENIGN and det.confidence[i] == 0
    assert any(v is Verdict.KNOWN_ATTACK for v in det.verdict) and any(v is Verdict.BENIGN for v in det.verdict)
    # DataFrame path and records path agree (RF averages trees in parallel, so compare with a tolerance)
    again = eng.detect(_records(b))
    assert np.allclose(again.p_attack, det.p_attack, atol=1e-9) and again.verdict == det.verdict


def test_binary_only_bundle_answers_malicious(bundles):
    b = load_bundle(f"local:{bundles['luflow']}")
    det = DetectionEngine(b).detect(_records(b))
    fams = {f for f, v in zip(det.family, det.verdict, strict=True) if v is Verdict.KNOWN_ATTACK}
    assert fams == {AttackFamily.MALICIOUS}


def test_tampering_missing_and_extra_files_are_refused(bundles, tmp_path):
    def fresh():
        d = tmp_path / "b"
        shutil.rmtree(d, ignore_errors=True)
        shutil.copytree(bundles["cic"], d)
        return d

    d = fresh(); (d / "thresholds.json").write_text('{"tau_binary": 0.01, "tau_anomaly": 1, "operating_fpr": 0.5}')  # noqa: E702
    with pytest.raises(BundleIntegrityError, match="sha256 mismatch"):
        load_bundle(f"local:{d}")
    d = fresh(); (d / "rf_binary.joblib").unlink()  # noqa: E702
    with pytest.raises(BundleIntegrityError, match="missing files"):
        load_bundle(f"local:{d}")
    d = fresh(); (d / "sneaky.py").write_text("print(1)")  # noqa: E702
    with pytest.raises(BundleIntegrityError, match="unlisted"):
        load_bundle(f"local:{d}")
    d = fresh(); (d / "manifest.json").unlink()  # noqa: E702
    with pytest.raises(BundleIntegrityError, match="no manifest"):
        load_bundle(f"local:{d}")


def test_packager_guards(bundles, tmp_path):
    b = load_bundle(f"local:{bundles['cic']}")
    common = dict(spec_path=bundles["cic"] / "feature_spec.json", transformer=b.transformer, rf_binary=b.rf_binary,
                  iforest=b.iforest, benign_val_scores=b.benign_val_scores, drift_reference=b.drift_reference,
                  baseline_stats=b.baseline_stats, dataset="t", split_strategy="t", metrics_summary={})
    with pytest.raises(FileExistsError):
        build_bundle(bundles["cic"], version="x", thresholds=b.thresholds, **common)
    with pytest.raises(ValueError, match="thresholds missing"):
        build_bundle(tmp_path / "x", version="x", thresholds={"tau_binary": 0.5}, **common)
    with pytest.raises(ValueError, match="at least 100"):
        build_bundle(tmp_path / "y", version="x", thresholds=b.thresholds,
                     **{**common, "benign_val_scores": np.arange(5)})
    other = bundles["luflow"] / "feature_spec.json"  # transformer fitted with the CIC spec, bundling the LUFlow spec
    with pytest.raises(ValueError, match="different feature spec"):
        build_bundle(tmp_path / "z", version="x", thresholds=b.thresholds, **{**common, "spec_path": other})


def test_ref_schemes():
    with pytest.raises(NotImplementedError):
        load_bundle("azureml:netsentinel-bundle@latest")
    with pytest.raises(ValueError, match="unknown bundle ref scheme"):
        load_bundle("s3:bucket/x")
    assert isinstance(pd.__version__, str)
