import json
from pathlib import Path

import pytest

from nscore.contracts import schemas as s
from nscore.contracts.policy import confidence_band, priority_band, priority_score
from nscore.detection.fusion import fuse, novel_confidence

FIX = Path(__file__).resolve().parents[1] / "nscore" / "contracts" / "fixtures"

FIXTURE_MODELS = {
    "flow_record.json": s.FlowRecord,
    "score_result.json": s.ScoreResult,
    "incident_page.json": s.IncidentPage,
    "incident_detail.json": s.IncidentDetail,
    "evaluation_report.json": s.EvaluationReport,
    "model_info.json": s.ModelInfo,
    "drift_report.json": s.DriftReport,
    "live_metrics.json": s.LiveMetrics,
}


@pytest.mark.parametrize("name,model", FIXTURE_MODELS.items())
def test_fixtures_validate(name, model):
    model.model_validate(json.loads((FIX / name).read_text(encoding="utf-8")))


def test_fusion_regions():
    assert fuse(0.9, 10, 0.6, 99.5) is s.Verdict.KNOWN_ATTACK
    assert fuse(0.2, 99.9, 0.6, 99.5) is s.Verdict.NOVEL_ANOMALY
    assert fuse(0.2, 50, 0.6, 99.5) is s.Verdict.BENIGN


def test_novel_confidence_range():
    assert novel_confidence(99.0, 99.5) == 0.0
    assert novel_confidence(99.5, 99.5) == 0.5
    assert novel_confidence(100.0, 99.5) == 1.0


def test_priority_monotonic_and_bounded():
    f, v = s.AttackFamily.BOTNET, s.Verdict.KNOWN_ATTACK
    assert priority_score(f, v, 0.5, 1) < priority_score(f, v, 0.9, 1) < priority_score(f, v, 0.9, 500)
    assert priority_score(f, v, 1.0, 10**6) == 90
    assert 0 <= priority_score(s.AttackFamily.UNKNOWN, s.Verdict.NOVEL_ANOMALY, 1.0, 10**6) <= 100
    assert priority_score(s.AttackFamily.BENIGN, s.Verdict.BENIGN, 1.0, 10) == 0
    assert priority_band(85) == "P1" and priority_band(10) == "P4"
    assert confidence_band(0.5) == "low"


def test_flow_batch_limits():
    with pytest.raises(ValueError):
        s.FlowBatch(flows=[])
