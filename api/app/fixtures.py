import json
from pathlib import Path
from typing import Any

from nscore.contracts import schemas

FIXTURES_DIR = Path(__file__).parent.parent.parent / "nscore" / "contracts" / "fixtures"

def load_fixture(filename: str) -> dict[str, Any]:
    with open(FIXTURES_DIR / filename) as f:
        return json.load(f)

def get_model_info() -> schemas.ModelInfo:
    return schemas.ModelInfo.model_validate(load_fixture("model_info.json"))

def get_evaluation_report() -> schemas.EvaluationReport:
    return schemas.EvaluationReport.model_validate(load_fixture("evaluation_report.json"))

def get_score_result() -> schemas.ScoreResult:
    return schemas.ScoreResult.model_validate(load_fixture("score_result.json"))

def get_incident_detail() -> schemas.IncidentDetail:
    return schemas.IncidentDetail.model_validate(load_fixture("incident_detail.json"))

def get_incident_page() -> schemas.IncidentPage:
    return schemas.IncidentPage.model_validate(load_fixture("incident_page.json"))

def get_drift_report() -> schemas.DriftReport:
    return schemas.DriftReport.model_validate(load_fixture("drift_report.json"))

def get_live_metrics() -> schemas.LiveMetrics:
    return schemas.LiveMetrics.model_validate(load_fixture("live_metrics.json"))
