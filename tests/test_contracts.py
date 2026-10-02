import json
from pathlib import Path

import pytest

from nscore.contracts import schemas as s
from nscore.contracts.policy import burst_factor, confidence_band, expected_severity, risk_level, risk_score
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


def test_risk_matches_team_worked_examples():
    # docs/reference/NetSentinel_Risk_Scoring_Pipeline.pdf, single flow (burst = 1.0)
    k = s.Verdict.KNOWN_ATTACK
    assert risk_score(k, 0.88, expected_severity(s.AttackFamily.BRUTE_FORCE)) == 62
    assert risk_score(k, 0.81, expected_severity(s.AttackFamily.INFILTRATION)) == 81
    assert risk_score(k, 0.95, expected_severity(s.AttackFamily.PORTSCAN)) == 28
    assert [risk_level(x) for x in (62, 81, 28)] == ["MEDIUM", "HIGH", "LOW"]


def test_risk_burst_and_bounds():
    k = s.Verdict.KNOWN_ATTACK
    one = risk_score(k, 0.9, 0.8, 1)
    assert one < risk_score(k, 0.9, 0.8, 100) < risk_score(k, 0.9, 0.8, 1000) == risk_score(k, 0.9, 0.8, 10**6)
    assert burst_factor(1) == 1.0 and abs(burst_factor(1000) - 1.15) < 1e-9
    assert risk_score(s.Verdict.NOVEL_ANOMALY, 1.0, 1.0, 10**6) == 100
    assert risk_score(s.Verdict.BENIGN, 1.0, 1.0, 10) == 0
    assert confidence_band(0.5) == "low"


def test_expected_severity_weights_by_probability():
    f = s.AttackFamily
    assert expected_severity(f.WEB_ATTACK, {f.WEB_ATTACK: 0.5, f.INFILTRATION: 0.5}) == 0.8
    assert expected_severity(f.MALICIOUS) == 0.7


def test_flow_batch_limits():
    with pytest.raises(ValueError):
        s.FlowBatch(flows=[])
