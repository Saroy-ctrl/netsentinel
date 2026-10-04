"""NetSentinel FastAPI application.

M3-01: Mock skeleton (NS_MOCK=1) — all endpoints return contract-typed fixtures.
M3-02: SQLite schema and repository layer.
M3-03: Real bundle loading at startup (MODEL_REF env var → load_bundle).
        /health, /v1/model, /v1/model/evaluation now served from the loaded Bundle
        when a bundle is present.  NS_MOCK=1 fallback is preserved for all paths.
M3-04: Real POST /v1/flows — DetectionEngine → SHAP → persist to SQLite.
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from api.app import fixtures
from api.app.db import db_session
from api.app.scoring import ScoringService
from nscore.bundle.loader import Bundle, load_bundle
from nscore.contracts import schemas
from nscore.features.transform import MissingFeaturesError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lifespan – bundle loading (M3-03)
# ---------------------------------------------------------------------------

_DEFAULT_MODEL_REF = "local:artifacts/bundles/mock-cic"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the model bundle at startup; clear it on shutdown."""
    ref = os.environ.get("MODEL_REF", _DEFAULT_MODEL_REF)
    try:
        bundle: Bundle = load_bundle(ref)
        app.state.bundle = bundle
        app.state.scorer = ScoringService(bundle)
        logger.info("M3-03/04: bundle loaded — version=%s ref=%s", bundle.version, ref)
    except Exception as exc:
        # In mock-only CI the default path may not exist; log and continue so
        # NS_MOCK=1 tests still run.  Any other failure is re-raised so the
        # operator knows the bundle is broken.
        if os.environ.get("NS_MOCK") == "1":
            app.state.bundle = None
            app.state.scorer = None
            logger.warning(
                "M3-03/04: bundle load failed in mock mode (NS_MOCK=1), continuing without bundle. "
                "Error: %s",
                exc,
            )
        else:
            raise
    yield
    app.state.bundle = None
    app.state.scorer = None


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="NetSentinel API", version="0.1.0", lifespan=lifespan)


def _is_mock() -> bool:
    """Check NS_MOCK at request time or fallback if no bundle is loaded."""
    if os.environ.get("NS_MOCK") == "1":
        return True
    
    if getattr(app.state, "bundle", None) is not None:
        return False
        
    db_path = os.environ.get("NS_DB_PATH")
    if db_path and os.path.exists(db_path):
        return False
        
    return True

def _bundle() -> Bundle | None:
    """Return the loaded Bundle, or None if not yet available."""
    try:
        return app.state.bundle
    except AttributeError:
        return None


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict[str, Any]:
    b = _bundle()
    if b is not None:
        return {"status": "ok", "model_loaded": True, "model_version": b.version}
    # NS_MOCK=1 fallback
    if _is_mock():
        info = fixtures.get_model_info()
        return {"status": "ok", "model_loaded": True, "model_version": info.model_version}
    return {"status": "ok", "model_loaded": False, "model_version": "unknown"}


# ---------------------------------------------------------------------------
# GET /v1/model
# ---------------------------------------------------------------------------


@app.get("/v1/model", response_model=schemas.ModelInfo)
def get_model_info():
    b = _bundle()
    if b is not None:
        return b.model_info()
    if _is_mock():
        return fixtures.get_model_info()
    raise HTTPException(status_code=501, detail="Not implemented")


# ---------------------------------------------------------------------------
# GET /v1/model/evaluation
# ---------------------------------------------------------------------------


@app.get("/v1/model/evaluation", response_model=schemas.EvaluationReport)
def get_model_evaluation():
    b = _bundle()
    if b is not None:
        if b.evaluation_report is None:
            raise HTTPException(status_code=404, detail="Evaluation report not present in this bundle")
        return schemas.EvaluationReport.model_validate(b.evaluation_report)
    if _is_mock():
        return fixtures.get_evaluation_report()
    raise HTTPException(status_code=501, detail="Not implemented")


# ---------------------------------------------------------------------------
# POST /v1/flows  (M3-01 mock only; real scoring in M3-04)
# ---------------------------------------------------------------------------


@app.post("/v1/flows", response_model=schemas.ScoreBatchResponse)
def score_flows(batch: schemas.FlowBatch, x_api_key: str | None = Header(None)):
    # M3-04 real path — takes precedence when bundle / scorer is loaded
    scorer: ScoringService | None = getattr(app.state, "scorer", None)
    if scorer is not None:
        try:
            # Resolve DB path at request time so NS_DB_PATH overrides work in tests
            _db_path = os.environ.get("NS_DB_PATH", "netsentinel.db")
            with db_session(_db_path) as conn:
                return scorer.score_batch(batch, conn)
        except MissingFeaturesError as exc:
            raise HTTPException(
                status_code=422,
                detail=f"Flow is missing required features: {', '.join(exc.missing)}",
            ) from exc

    # M3-01 mock path — preserved for NS_MOCK=1 when no bundle is loaded
    if _is_mock():
        result = fixtures.get_score_result()
        return schemas.ScoreBatchResponse(
            received=len(batch.flows),
            results=[result for _ in batch.flows],
            incidents_created=1,
            incidents_updated=0,
        )

    raise HTTPException(status_code=503, detail="Model bundle not loaded")


# ---------------------------------------------------------------------------
# Incident endpoints  (M3-01 mock only; real DB in M3-07)
# ---------------------------------------------------------------------------


@app.get("/v1/incidents", response_model=schemas.IncidentPage)
def get_incidents(
    status: str | None = None,
    verdict: str | None = None,
    family: str | None = None,
    level: str | None = None,
    since: str | None = None,
    limit: int = 50,
    offset: int = 0,
    sort: str = "risk",
):
    if _is_mock():
        return fixtures.get_incident_page()
    
    _db_path = os.environ.get("NS_DB_PATH", "netsentinel.db")
    with db_session(_db_path) as conn:
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        
        if status:
            query += " AND status = ?"
            params.append(status)
        if verdict:
            query += " AND verdict = ?"
            params.append(verdict)
        if family:
            query += " AND attack_family = ?"
            params.append(family)
        if level:
            query += " AND risk_level = ?"
            params.append(level)
        if since:
            query += " AND first_seen >= ?"
            params.append(since)
            
        count_query = f"SELECT COUNT(*) FROM ({query})"
        total = conn.execute(count_query, params).fetchone()[0]
        
        if sort == "risk":
            query += " ORDER BY risk_score DESC"
        elif sort == "last_seen":
            query += " ORDER BY last_seen DESC"
        else:
            query += " ORDER BY risk_score DESC"
            
        query += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        rows = conn.execute(query, params).fetchall()
        items = []
        for row in rows:
            item_dict = dict(row)
            item_dict["mitre_technique_id"] = item_dict.pop("mitre_id", None)
            item_dict["mitre_technique_name"] = item_dict.pop("mitre_name", None)
            item_dict.pop("top_features_json", None)
            item_dict.pop("brief_json", None)
            item_dict.pop("acknowledged_at", None)
            item_dict.pop("updated_at", None)
            items.append(schemas.IncidentSummary.model_validate(item_dict))
            
        return schemas.IncidentPage(items=items, total=total, limit=limit, offset=offset)


@app.get("/v1/incidents/{incident_id}", response_model=schemas.IncidentDetail)
def get_incident(incident_id: str):
    if _is_mock():
        detail = fixtures.get_incident_detail()
        detail.incident_id = incident_id
        return detail

    _db_path = os.environ.get("NS_DB_PATH", "netsentinel.db")
    with db_session(_db_path) as conn:
        row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        item_dict = dict(row)
        item_dict["mitre_technique_id"] = item_dict.pop("mitre_id", None)
        item_dict["mitre_technique_name"] = item_dict.pop("mitre_name", None)
        item_dict.pop("acknowledged_at", None)
        item_dict.pop("updated_at", None)
        
        tf_json = item_dict.pop("top_features_json", None)
        if tf_json:
            item_dict["top_features"] = json.loads(tf_json)
        else:
            item_dict["top_features"] = []
            
        bf_json = item_dict.pop("brief_json", None)
        if bf_json:
            item_dict["brief"] = json.loads(bf_json)
            
        flow_rows = conn.execute("SELECT flow_id FROM flows WHERE incident_id = ? LIMIT 20", (incident_id,)).fetchall()
        item_dict["sample_flow_ids"] = [r["flow_id"] for r in flow_rows]
        
        action_rows = conn.execute(
            "SELECT * FROM analyst_actions WHERE incident_id = ? ORDER BY at ASC",
            (incident_id,),
        ).fetchall()
        item_dict["actions"] = [dict(r) for r in action_rows]
        
        return schemas.IncidentDetail.model_validate(item_dict)


@app.post("/v1/incidents/{incident_id}/actions", response_model=schemas.AnalystActionRecord)
def add_incident_action(
    incident_id: str,
    action: schemas.AnalystActionIn,
    x_analyst: str | None = Header(None),
):
    if not x_analyst:
        raise HTTPException(status_code=422, detail="X-Analyst header is required")

    if _is_mock():
        return schemas.AnalystActionRecord(
            action_id=1,
            incident_id=incident_id,
            analyst=x_analyst,
            action=action.action,
            note=action.note,
            at=datetime.utcnow(),
        )

    _db_path = os.environ.get("NS_DB_PATH", "netsentinel.db")
    with db_session(_db_path) as conn:
        row = conn.execute("SELECT status, acknowledged_at FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        current_status = row["status"]
        if current_status in ("dismissed_fp", "resolved"):
            raise HTTPException(status_code=400, detail="Cannot perform actions on a closed incident")
            
        new_status = current_status
        if action.action == "acknowledge":
            new_status = "acknowledged"
        elif action.action == "escalate":
            new_status = "escalated"
        elif action.action == "dismiss_fp":
            new_status = "dismissed_fp"
        elif action.action == "resolve":
            new_status = "resolved"
            
        from datetime import timezone
        now_str = datetime.now(timezone.utc).isoformat()
        
        update_query = "UPDATE incidents SET status = ?, updated_at = ?"
        update_params = [new_status, now_str]
        
        if action.action == "acknowledge" and current_status == "new" and row["acknowledged_at"] is None:
            update_query += ", acknowledged_at = ?"
            update_params.append(now_str)
            
        update_query += " WHERE incident_id = ?"
        update_params.append(incident_id)
        
        conn.execute(update_query, update_params)
        
        cursor = conn.execute(
            "INSERT INTO analyst_actions (incident_id, analyst, action, note, at) VALUES (?, ?, ?, ?, ?)",
            (incident_id, x_analyst, action.action.value, action.note, now_str)
        )
        action_id = cursor.lastrowid
        
        conn.commit()
        
        return schemas.AnalystActionRecord(
            action_id=action_id,
            incident_id=incident_id,
            analyst=x_analyst,
            action=action.action,
            note=action.note,
            at=datetime.fromisoformat(now_str),
        )


@app.get("/v1/incidents/{incident_id}/brief", response_model=schemas.Brief)
def get_incident_brief(incident_id: str, refresh: bool = False):
    if _is_mock():
        detail = fixtures.get_incident_detail()
        if detail.brief:
            detail.brief.incident_id = incident_id
            return detail.brief
        return schemas.Brief(
            incident_id=incident_id,
            text="Mock brief for incident",
            source="template",
            confidence_band="high",
            generated_at=datetime.utcnow(),
        )
    raise HTTPException(status_code=501, detail="Not implemented")


# ---------------------------------------------------------------------------
# Ops endpoints  (M3-01 mock only)
# ---------------------------------------------------------------------------


@app.get("/v1/drift", response_model=schemas.DriftReport)
def get_drift():
    if _is_mock():
        return fixtures.get_drift_report()
    raise HTTPException(status_code=501, detail="Not implemented")


@app.get("/v1/metrics", response_model=schemas.LiveMetrics)
def get_metrics():
    if _is_mock():
        return fixtures.get_live_metrics()
    raise HTTPException(status_code=501, detail="Not implemented")


class ReloadRequest(BaseModel):
    model_ref: str


@app.post("/v1/admin/reload-model", response_model=schemas.ModelInfo)
def reload_model(req: ReloadRequest):
    if _is_mock():
        return fixtures.get_model_info()
    raise HTTPException(status_code=501, detail="Not implemented")
