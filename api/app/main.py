import os
from typing import Any
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import datetime

from nscore.contracts import schemas
from api.app import fixtures

app = FastAPI(title="NetSentinel API", version="0.1.0")

# Check mock mode
IS_MOCK = os.environ.get("NS_MOCK") == "1"

@app.get("/health")
def health() -> dict[str, Any]:
    if IS_MOCK:
        info = fixtures.get_model_info()
        return {
            "status": "ok",
            "model_loaded": True,
            "model_version": info.model_version
        }
    return {"status": "ok", "model_loaded": False, "model_version": "unknown"}

@app.get("/v1/model", response_model=schemas.ModelInfo)
def get_model_info():
    if IS_MOCK:
        return fixtures.get_model_info()
    raise HTTPException(status_code=501, detail="Not implemented")

@app.get("/v1/model/evaluation", response_model=schemas.EvaluationReport)
def get_model_evaluation():
    if IS_MOCK:
        return fixtures.get_evaluation_report()
    raise HTTPException(status_code=501, detail="Not implemented")

@app.post("/v1/flows", response_model=schemas.ScoreBatchResponse)
def score_flows(batch: schemas.FlowBatch, x_api_key: str | None = Header(None)):
    if IS_MOCK:
        result = fixtures.get_score_result()
        return schemas.ScoreBatchResponse(
            received=len(batch.flows),
            results=[result for _ in batch.flows],
            incidents_created=1,
            incidents_updated=0
        )
    raise HTTPException(status_code=501, detail="Not implemented")

@app.get("/v1/incidents", response_model=schemas.IncidentPage)
def get_incidents(
    status: str | None = None,
    verdict: str | None = None,
    family: str | None = None,
    level: str | None = None,
    since: str | None = None,
    limit: int = 50,
    offset: int = 0,
    sort: str = "risk"
):
    if IS_MOCK:
        return fixtures.get_incident_page()
    raise HTTPException(status_code=501, detail="Not implemented")

@app.get("/v1/incidents/{incident_id}", response_model=schemas.IncidentDetail)
def get_incident(incident_id: str):
    if IS_MOCK:
        detail = fixtures.get_incident_detail()
        detail.incident_id = incident_id
        return detail
    raise HTTPException(status_code=501, detail="Not implemented")

@app.post("/v1/incidents/{incident_id}/actions", response_model=schemas.AnalystActionRecord)
def add_incident_action(incident_id: str, action: schemas.AnalystActionIn, x_analyst: str | None = Header(None)):
    if IS_MOCK:
        return schemas.AnalystActionRecord(
            action_id=1,
            incident_id=incident_id,
            analyst=x_analyst or "mock_analyst",
            action=action.action,
            note=action.note,
            at=datetime.utcnow()
        )
    raise HTTPException(status_code=501, detail="Not implemented")

@app.get("/v1/incidents/{incident_id}/brief", response_model=schemas.Brief)
def get_incident_brief(incident_id: str, refresh: bool = False):
    if IS_MOCK:
        detail = fixtures.get_incident_detail()
        if detail.brief:
            detail.brief.incident_id = incident_id
            return detail.brief
        return schemas.Brief(
            incident_id=incident_id,
            text="Mock brief for incident",
            source="template",
            confidence_band="high",
            generated_at=datetime.utcnow()
        )
    raise HTTPException(status_code=501, detail="Not implemented")

@app.get("/v1/drift", response_model=schemas.DriftReport)
def get_drift():
    if IS_MOCK:
        return fixtures.get_drift_report()
    raise HTTPException(status_code=501, detail="Not implemented")

@app.get("/v1/metrics", response_model=schemas.LiveMetrics)
def get_metrics():
    if IS_MOCK:
        return fixtures.get_live_metrics()
    raise HTTPException(status_code=501, detail="Not implemented")

class ReloadRequest(BaseModel):
    model_ref: str

@app.post("/v1/admin/reload-model", response_model=schemas.ModelInfo)
def reload_model(req: ReloadRequest):
    if IS_MOCK:
        return fixtures.get_model_info()
    raise HTTPException(status_code=501, detail="Not implemented")
