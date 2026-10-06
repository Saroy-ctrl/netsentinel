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
import re
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from api.app import fixtures
from api.app.db import db_session, get_connection
from api.app.repository import Repository
from api.app.scoring import ScoringService
from api.app.services.brief import generate_and_cache_brief
from api.app.services.drift import DriftMonitor
from nscore.bundle.loader import Bundle, load_bundle
from nscore.contracts import schemas
from nscore.features.transform import MissingFeaturesError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lifespan – bundle loading (M3-03)
# ---------------------------------------------------------------------------

_DEFAULT_MODEL_REF = "local:artifacts/bundles/mock-cic"


@dataclass
class ModelContext:
    bundle: Bundle | None = None
    scorer: ScoringService | None = None
    drift_monitor: DriftMonitor | None = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the model bundle at startup; clear it on shutdown."""
    ref = os.environ.get("MODEL_REF", _DEFAULT_MODEL_REF)
    try:
        bundle: Bundle = load_bundle(ref)
        scorer = ScoringService(bundle)
        _startup_db = os.environ.get("NS_DB_PATH", "netsentinel.db")
        drift_monitor = DriftMonitor(bundle, _startup_db)
        app.state.model_ctx = ModelContext(bundle, scorer, drift_monitor)
        logger.info("M3-03/04: bundle loaded — version=%s ref=%s", bundle.version, ref)
    except Exception as exc:
        if os.environ.get("NS_MOCK") == "1":
            app.state.model_ctx = ModelContext()
            logger.warning(
                "M3-03/04: bundle load failed in mock mode (NS_MOCK=1), continuing without bundle. "
                "Error: %s",
                exc,
            )
        else:
            raise
    yield
    app.state.model_ctx = ModelContext()


# ---------------------------------------------------------------------------
# App & Middleware
# ---------------------------------------------------------------------------

app = FastAPI(title="NetSentinel API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def structured_logging_middleware(request: Request, call_next):
    req_id = uuid.uuid4().hex
    start_time = time.perf_counter()
    
    response = await call_next(request)
    
    duration = time.perf_counter() - start_time
    
    log_data = {
        "request_id": req_id,
        "method": request.method,
        "url": str(request.url),
        "status_code": response.status_code,
        "duration_ms": round(duration * 1000, 2)
    }
    logger.info(json.dumps(log_data))
    
    response.headers["X-Request-ID"] = req_id
    return response

@app.exception_handler(MissingFeaturesError)
async def missing_features_handler(request: Request, exc: MissingFeaturesError):
    errors = [
        {
            "loc": ["body", "flows", feat],
            "msg": f"Missing required feature: {feat}",
            "type": "value_error.missing"
        }
        for feat in exc.missing
    ]
    return JSONResponse(status_code=422, content={"detail": errors})


# ---------------------------------------------------------------------------
# Auth Dependencies
# ---------------------------------------------------------------------------

def verify_api_key(x_api_key: str | None = Header(None)):
    # Always enforced: mock mode swaps the scoring backend, never the authentication.
    expected_key = os.environ.get("NS_API_KEY", "test_api_key")
    if not x_api_key or x_api_key != expected_key:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid or missing API key")
    return x_api_key

def verify_admin_key(x_admin_key: str | None = Header(None)):
    expected_key = os.environ.get("NS_ADMIN_KEY", "admin_secret")
    if not x_admin_key or x_admin_key != expected_key:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid or missing Admin API key")
    return x_admin_key

def verify_analyst(x_analyst: str | None = Header(None)):
    if not x_analyst:
        raise HTTPException(status_code=422, detail="X-Analyst header is required")
    if not re.match(r"^[\w\s\-]+\+[\w\s\-]+$", x_analyst):
        raise HTTPException(status_code=422, detail="X-Analyst must be in 'Name + Role' format")
    return x_analyst


def _is_mock() -> bool:
    """Check NS_MOCK at request time or fallback if no bundle is loaded."""
    if os.environ.get("NS_MOCK") == "1":
        return True
    
    ctx = getattr(app.state, "model_ctx", None)
    if ctx and ctx.bundle is not None:
        return False
        
    db_path = os.environ.get("NS_DB_PATH")
    if db_path and os.path.exists(db_path):
        return False
        
    return True

def _bundle() -> Bundle | None:
    """Return the loaded Bundle, or None if not yet available."""
    ctx = getattr(app.state, "model_ctx", None)
    return ctx.bundle if ctx else None


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
def score_flows(batch: schemas.FlowBatch, x_api_key: str = Depends(verify_api_key)):
    # M3-04 real path — takes precedence when bundle / scorer is loaded
    ctx = getattr(app.state, "model_ctx", None)
    scorer = ctx.scorer if ctx else None
    if scorer is not None:
        # Resolve DB path at request time so NS_DB_PATH overrides work in tests
        _db_path = os.environ.get("NS_DB_PATH", "netsentinel.db")
        drift_monitor = ctx.drift_monitor if ctx else None
        with db_session(_db_path) as conn:
            return scorer.score_batch(batch, conn, drift_monitor=drift_monitor)

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
            item_dict.pop("shap_n", None)
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
        item_dict.pop("shap_n", None)
        
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
    x_analyst: str = Depends(verify_analyst),
):
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
        row = conn.execute(
            "SELECT status, acknowledged_at FROM incidents WHERE incident_id = ?", 
            (incident_id,)
        ).fetchone()
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
            
        now_str = datetime.now(UTC).isoformat()
        
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
async def get_incident_brief(incident_id: str, refresh: bool = False):
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

    _db_path = os.environ.get("NS_DB_PATH", "netsentinel.db")
    with db_session(_db_path) as conn:
        repo = Repository(conn)
        row = repo.get_incident(incident_id)
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        incident_data = dict(row)
        
    # We generate/cache outside the with-block to not hold DB connection during LLM wait
    brief = await generate_and_cache_brief(incident_id, incident_data, Repository(get_connection(_db_path)), refresh)
    return brief


# ---------------------------------------------------------------------------
# Ops endpoints  (M3-01 mock only)
# ---------------------------------------------------------------------------


@app.get("/v1/drift", response_model=schemas.DriftReport)
def get_drift():
    if _is_mock():
        return fixtures.get_drift_report()

    ctx = getattr(app.state, "model_ctx", None)
    monitor = ctx.drift_monitor if ctx else getattr(app.state, "drift_monitor", None)
    if monitor is not None:
        report = monitor.get_latest_report()
        if report is not None:
            return report

    raise HTTPException(status_code=404, detail="No drift snapshot available yet")


@app.get("/v1/metrics", response_model=schemas.LiveMetrics)
def get_metrics():
    if _is_mock():
        return fixtures.get_live_metrics()


    import numpy as np

    _db_path = os.environ.get("NS_DB_PATH", "netsentinel.db")
    with db_session(_db_path) as conn:
        # -- Throughput -------------------------------------------------------
        flows_total: int = conn.execute(
            "SELECT COUNT(*) FROM flows"
        ).fetchone()[0]

        flows_last_60s: int = conn.execute(
            "SELECT COUNT(*) FROM flows "
            "WHERE received_at >= datetime('now', '-60 seconds')"
        ).fetchone()[0]
        flows_per_sec: float = flows_last_60s / 60.0

        # -- Latency percentiles ----------------------------------------------
        lat_rows = conn.execute(
            "SELECT latency_ms FROM flows WHERE latency_ms IS NOT NULL"
        ).fetchall()
        if lat_rows:
            lat_arr = np.array([r[0] for r in lat_rows], dtype=np.float64)
            p50 = float(np.percentile(lat_arr, 50))
            p95 = float(np.percentile(lat_arr, 95))
        else:
            p50, p95 = 0.0, 0.0

        # -- Open incidents ---------------------------------------------------
        open_rows = conn.execute(
            "SELECT risk_level FROM incidents "
            "WHERE status NOT IN ('resolved', 'dismissed_fp')"
        ).fetchall()
        incidents_open: int = len(open_rows)
        by_level: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in open_rows:
            lv = r[0]
            if lv in by_level:
                by_level[lv] += 1

        # -- Analyst-confirmed precision & FP dismiss rate --------------------
        reviewed = conn.execute(
            "SELECT action FROM analyst_actions "
            "WHERE action IN ('confirm', 'dismiss_fp')"
        ).fetchall()
        confirmed = sum(1 for r in reviewed if r[0] == "confirm")
        dismissed_fp = sum(1 for r in reviewed if r[0] == "dismiss_fp")
        total_reviewed = confirmed + dismissed_fp
        precision: float | None = confirmed / total_reviewed if total_reviewed else None
        fp_rate: float | None = dismissed_fp / total_reviewed if total_reviewed else None

        # -- MTTA (mean time to acknowledge in seconds) -----------------------
        mtta_rows = conn.execute(
            "SELECT first_seen, acknowledged_at FROM incidents "
            "WHERE acknowledged_at IS NOT NULL AND first_seen IS NOT NULL"
        ).fetchall()
        mtta: float | None = None
        if mtta_rows:
            from datetime import datetime as _dt
            deltas: list[float] = []
            for r in mtta_rows:
                try:
                    fs = _dt.fromisoformat(r[0].replace("Z", "+00:00"))
                    ack = _dt.fromisoformat(r[1].replace("Z", "+00:00"))
                    delta = (ack - fs).total_seconds()
                    if delta >= 0:
                        deltas.append(delta)
                except Exception:
                    pass
            mtta = float(np.mean(deltas)) if deltas else None

    return schemas.LiveMetrics(
        flows_scored_total=flows_total,
        flows_per_sec_1m=flows_per_sec,
        latency_ms_p50=p50,
        latency_ms_p95=p95,
        incidents_open=incidents_open,
        incidents_by_level=by_level,
        analyst_confirmed_precision=precision,
        fp_dismiss_rate=fp_rate,
        mtta_seconds=mtta,
    )


class ReloadRequest(BaseModel):
    model_ref: str


@app.post("/v1/admin/reload-model", response_model=schemas.ModelInfo)
def reload_model(req: ReloadRequest, x_admin_key: str = Depends(verify_admin_key)):
    if _is_mock():
        return fixtures.get_model_info()

    try:
        new_bundle = load_bundle(req.model_ref)
        new_scorer = ScoringService(new_bundle)
        _startup_db = os.environ.get("NS_DB_PATH", "netsentinel.db")
        new_monitor = DriftMonitor(new_bundle, _startup_db)
        app.state.model_ctx = ModelContext(new_bundle, new_scorer, new_monitor)
        return new_bundle.model_info()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
