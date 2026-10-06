"""NetSentinel SOC Dashboard — API client.

All API access is isolated in this module.  Nothing in `dashboard/` should
import `httpx` or read fixture files directly — everything goes through here.

Data-source selection (checked in order):
  1. NS_OFFLINE=1              → read nscore/contracts/fixtures/*.json directly
  2. NS_API_URL=http://…       → HTTP calls to that URL (live API or NS_MOCK=1 API)
  3. (nothing set)             → offline mode with a console warning

Every public function returns a typed Pydantic model from nscore.contracts.schemas,
or raises APIError on failure.  The caller (page code) handles errors; this module
never calls `st.error()` directly.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC
from pathlib import Path
from typing import Any

import httpx

from nscore.contracts.schemas import (
    CONTRACT_VERSION,
    AnalystActionIn,
    AnalystActionRecord,
    Brief,
    DriftReport,
    EvaluationReport,
    IncidentDetail,
    IncidentPage,
    LiveMetrics,
    ModelInfo,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config resolution
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).parent.parent / "nscore" / "contracts" / "fixtures"

def is_offline() -> bool:
    """Return True if offline fixture mode is requested or if NS_API_URL is missing."""
    val = os.environ.get("NS_OFFLINE", "").strip().lower()
    if val in ("1", "true", "yes"):
        return True
    if val in ("0", "false", "no"):
        return False
    return not bool(os.environ.get("NS_API_URL", "").strip())


def get_api_url() -> str:
    """Return the resolved base URL of the NetSentinel backend API."""
    return os.environ.get("NS_API_URL", "").rstrip("/")


_OFFLINE: bool = is_offline()
_API_URL: str = get_api_url()


def _data_source() -> str:
    """Human-readable label for the current data source."""
    if is_offline():
        return "offline (fixtures)"
    return f"API ({get_api_url()})"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class APIError(Exception):
    """Raised when the API call fails or returns an unexpected status."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _fixture(name: str) -> dict[str, Any]:
    """Load a fixture JSON file by stem name (e.g. 'incident_page')."""
    path = _FIXTURES_DIR / f"{name}.json"
    if not path.exists():
        raise APIError(f"Fixture file not found: {path}")
    with path.open() as f:
        return json.load(f)


def _get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """HTTP GET against NS_API_URL.  Returns parsed JSON dict."""
    url = f"{get_api_url()}{path}"
    try:
        r = httpx.get(url, params=params, timeout=10.0)
        r.raise_for_status()
        return r.json()
    except httpx.TimeoutException as exc:
        raise APIError(f"Timeout reaching {url}") from exc
    except httpx.HTTPStatusError as exc:
        raise APIError(
            f"HTTP {exc.response.status_code} from {url}: {exc.response.text}",
            status_code=exc.response.status_code,
        ) from exc
    except httpx.RequestError as exc:
        raise APIError(f"Network error reaching {url}: {exc}") from exc


def _post(path: str, body: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
    """HTTP POST against NS_API_URL.  Returns parsed JSON dict."""
    url = f"{get_api_url()}{path}"
    try:
        r = httpx.post(url, json=body, headers=headers or {}, timeout=10.0)
        r.raise_for_status()
        return r.json()
    except httpx.TimeoutException as exc:
        raise APIError(f"Timeout reaching {url}") from exc
    except httpx.HTTPStatusError as exc:
        raise APIError(
            f"HTTP {exc.response.status_code} from {url}: {exc.response.text}",
            status_code=exc.response.status_code,
        ) from exc
    except httpx.RequestError as exc:
        raise APIError(f"Network error reaching {url}: {exc}") from exc


# ---------------------------------------------------------------------------
# Public API functions — one per logical endpoint
# ---------------------------------------------------------------------------


def get_model_info() -> ModelInfo:
    """GET /v1/model — loaded bundle info (version, family_head, thresholds, …)."""
    if is_offline():
        return ModelInfo.model_validate(_fixture("model_info"))
    return ModelInfo.model_validate(_get("/v1/model"))


def get_evaluation() -> EvaluationReport:
    """GET /v1/model/evaluation — per-class metrics, LOAO, external, limitations."""
    if is_offline():
        return EvaluationReport.model_validate(_fixture("evaluation_report"))
    return EvaluationReport.model_validate(_get("/v1/model/evaluation"))


def get_incidents(
    *,
    status: str | None = None,
    verdict: str | None = None,
    family: str | None = None,
    level: str | None = None,
    since: str | None = None,
    limit: int = 50,
    offset: int = 0,
    sort: str = "risk",
) -> IncidentPage:
    """GET /v1/incidents — paginated, filtered incident list."""
    if is_offline():
        # Offline: load fixture and apply basic in-process filtering
        page = IncidentPage.model_validate(_fixture("incident_page"))
        items = page.items
        if status:
            items = [i for i in items if i.status.value == status]
        if verdict:
            items = [i for i in items if i.verdict.value == verdict]
        if family:
            items = [i for i in items if i.attack_family.value == family]
        if level:
            items = [i for i in items if i.risk_level == level]
        # Always sort by risk_score descending (matches live behaviour)
        items = sorted(items, key=lambda i: i.risk_score, reverse=True)
        total = len(items)
        items = items[offset : offset + limit]
        return IncidentPage(items=items, total=total, limit=limit, offset=offset)

    params: dict[str, Any] = {"limit": limit, "offset": offset, "sort": sort}
    if status:
        params["status"] = status
    if verdict:
        params["verdict"] = verdict
    if family:
        params["family"] = family
    if level:
        params["level"] = level
    if since:
        params["since"] = since
    return IncidentPage.model_validate(_get("/v1/incidents", params=params))


def get_incident(incident_id: str) -> IncidentDetail:
    """GET /v1/incidents/{id} — full detail including SHAP, actions, brief."""
    if is_offline():
        detail_data = _fixture("incident_detail")
        if incident_id and incident_id != detail_data.get("incident_id"):
            page_data = _fixture("incident_page")
            for item in page_data.get("items", []):
                if item.get("incident_id") == incident_id:
                    merged = dict(detail_data)
                    merged.update(item)
                    if merged.get("brief"):
                        b = dict(merged["brief"])
                        b["incident_id"] = incident_id
                        merged["brief"] = b
                    return IncidentDetail.model_validate(merged)
        return IncidentDetail.model_validate(detail_data)
    return IncidentDetail.model_validate(_get(f"/v1/incidents/{incident_id}"))


def get_brief(incident_id: str, *, refresh: bool = False) -> Brief:
    """GET /v1/incidents/{id}/brief — LLM or template brief."""
    if is_offline():
        detail = IncidentDetail.model_validate(_fixture("incident_detail"))
        if detail.brief is None:
            raise APIError("Fixture incident has no brief")
        return detail.brief
    params = {"refresh": "true" if refresh else "false"}
    return Brief.model_validate(_get(f"/v1/incidents/{incident_id}/brief", params=params))


_offline_action_counter = 1000


def post_action(
    incident_id: str,
    action: AnalystActionIn,
    *,
    analyst: str,
) -> AnalystActionRecord:
    """POST /v1/incidents/{id}/actions — acknowledge, escalate, confirm, dismiss_fp, etc."""
    if is_offline():
        # Return a synthetic record so the UI can show feedback without a live API.
        from datetime import datetime

        global _offline_action_counter
        _offline_action_counter += 1
        return AnalystActionRecord(
            action_id=_offline_action_counter,
            incident_id=incident_id,
            analyst=analyst,
            action=action.action,
            note=action.note,
            at=datetime.now(tz=UTC),
        )
    headers = {"X-Analyst": analyst}
    return AnalystActionRecord.model_validate(
        _post(f"/v1/incidents/{incident_id}/actions", body=action.model_dump(), headers=headers)
    )


def get_drift() -> DriftReport:
    """GET /v1/drift — PSI per feature + overall status."""
    if is_offline():
        return DriftReport.model_validate(_fixture("drift_report"))
    return DriftReport.model_validate(_get("/v1/drift"))


def get_live_metrics() -> LiveMetrics:
    """GET /v1/metrics — throughput, latency, analyst stats."""
    if is_offline():
        return LiveMetrics.model_validate(_fixture("live_metrics"))
    return LiveMetrics.model_validate(_get("/v1/metrics"))


def health_check() -> dict[str, Any]:
    """GET /health — returns raw dict (lightweight; used for API-down banner)."""
    if is_offline():
        return {"status": "ok", "mode": "offline", "contract_version": CONTRACT_VERSION}
    return _get("/health")


# ---------------------------------------------------------------------------
# Convenience info for the UI sidebar
# ---------------------------------------------------------------------------


def data_source_label() -> str:
    return _data_source()
