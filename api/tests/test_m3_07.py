"""M3-07 tests: Incident List, Detail, and Triage endpoints.

Covers:
  GET  /v1/incidents         — filtering (status, verdict, family, level, since),
                               sorting (risk DESC, last_seen DESC), pagination
  GET  /v1/incidents/{id}    — detail retrieval (flows, actions, top_features), 404
  POST /v1/incidents/{id}/actions — X-Analyst header enforcement, status transitions,
                                    terminal-state blocking, MTTA logic, audit log
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from api.app.db import db_session, get_connection
from api.app.main import ModelContext, app
from scripts.init_db import init_db

# ---------------------------------------------------------------------------
# Shared seed timestamps
# ---------------------------------------------------------------------------

_NOW = "2026-10-04T12:00:00Z"
_JAN = "2026-01-01T00:00:00Z"
_FEB = "2026-02-01T00:00:00Z"

# Top-features JSON for inc_1 — one feature entry (baseline_median omitted: optional)
_FEAT_JSON = '[{"feature": "f1", "value": 1.0, "shap_value": 0.5, "baseline_median": 0.1}]'


# ---------------------------------------------------------------------------
# Fixture: isolated DB + seeded data + TestClient (real-DB, NS_MOCK off)
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(tmp_path):
    """
    Spin up an isolated SQLite DB, seed it with 3 incidents + 2 flows + 1 action,
    then yield a TestClient that exercises the real-DB endpoints (NS_MOCK unset).
    """
    db_path = str(tmp_path / "test_m307.db")

    # Point every request at this isolated DB
    os.environ["NS_DB_PATH"] = db_path
    os.environ.pop("NS_MOCK", None)

    init_db(db_path)

    with get_connection(db_path) as conn:
        conn.executescript(f"""
            INSERT INTO incidents (
                incident_id, status, verdict, attack_family,
                risk_score, risk_level, severity, max_confidence,
                flow_count, src_ip, dst_ip, dst_port,
                first_seen, last_seen, model_version, top_features_json
            ) VALUES
            ('inc_1','new','known_attack','Infiltration',
             90,'HIGH',0.9,0.9,10,'1.1.1.1','2.2.2.2',80,
             '{_NOW}','{_NOW}','v1','{_FEAT_JSON}'),
            ('inc_2','acknowledged','novel_anomaly','Unknown',
             60,'MEDIUM',0.6,0.7,5,'3.3.3.3','4.4.4.4',443,
             '{_JAN}','{_JAN}','v1','[]'),
            ('inc_3','resolved','known_attack','DoS',
             30,'LOW',0.3,0.8,1,'5.5.5.5','6.6.6.6',8080,
             '{_FEB}','{_FEB}','v1','[]');

            INSERT INTO flows (
                flow_id, incident_id,
                src_ip, dst_ip, src_port, dst_port, protocol,
                features_json, verdict, p_attack, anomaly_pct,
                attack_family, severity, model_version, latency_ms
            ) VALUES
            ('f1','inc_1','1.1.1.1','2.2.2.2',12345,80,6,
             '{{}}','known_attack',0.9,0,'Infiltration',0.9,'v1',1.0),
            ('f2','inc_1','1.1.1.1','2.2.2.2',12346,80,6,
             '{{}}','known_attack',0.9,0,'Infiltration',0.9,'v1',1.0);

            INSERT INTO analyst_actions (incident_id, analyst, action, note, at)
            VALUES ('inc_2','Alice','acknowledge','first look','{_JAN}');
        """)
        conn.commit()

    # Inject state so lifespan bundle-load doesn't run (no bundle path configured)
    prior_ctx = getattr(app.state, "model_ctx", None)
    app.state.model_ctx = ModelContext(None, None, None)

    # Do NOT use TestClient as a context manager — that would invoke lifespan
    # which tries to load the ML bundle (no MODEL_REF set → load error → test crash).
    # Injecting app.state directly and using TestClient without 'with' avoids
    # the lifespan entirely, which is correct for incident-API-only tests.
    client = TestClient(app, raise_server_exceptions=True)
    yield client

    # Restore
    app.state.model_ctx = prior_ctx
    os.environ.pop("NS_DB_PATH", None)


# ---------------------------------------------------------------------------
# Helper: direct DB read (used by action/MTTA/audit-log tests)
# ---------------------------------------------------------------------------


def _inc_row(incident_id: str) -> dict:
    db_path = os.environ["NS_DB_PATH"]
    with db_session(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
    return dict(row) if row else {}


def _audit_rows(incident_id: str) -> list[dict]:
    db_path = os.environ["NS_DB_PATH"]
    with db_session(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM analyst_actions WHERE incident_id = ? ORDER BY action_id",
            (incident_id,),
        ).fetchall()
    return [dict(r) for r in rows]


# ===========================================================================
# 1. GET /v1/incidents — Filtering
# ===========================================================================


class TestIncidentFiltering:
    """All supported query-parameter filters return correct subsets."""

    def test_filter_status_new(self, client):
        res = client.get("/v1/incidents?status=new")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert data["items"][0]["incident_id"] == "inc_1"

    def test_filter_status_acknowledged(self, client):
        res = client.get("/v1/incidents?status=acknowledged")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert data["items"][0]["incident_id"] == "inc_2"

    def test_filter_verdict(self, client):
        res = client.get("/v1/incidents?verdict=novel_anomaly")
        assert res.status_code == 200
        assert res.json()["total"] == 1
        assert res.json()["items"][0]["incident_id"] == "inc_2"

    def test_filter_family(self, client):
        res = client.get("/v1/incidents?family=Unknown")
        assert res.status_code == 200
        assert res.json()["total"] == 1
        assert res.json()["items"][0]["incident_id"] == "inc_2"

    def test_filter_level_high(self, client):
        res = client.get("/v1/incidents?level=HIGH")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert data["items"][0]["incident_id"] == "inc_1"

    def test_filter_level_low(self, client):
        res = client.get("/v1/incidents?level=LOW")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert data["items"][0]["incident_id"] == "inc_3"

    def test_filter_since_excludes_old(self, client):
        # since=2026-06-01 excludes inc_2 (Jan) and inc_3 (Feb); only inc_1 (Oct) survives
        res = client.get("/v1/incidents?since=2026-06-01T00:00:00Z")
        assert res.status_code == 200
        data = res.json()
        ids = {i["incident_id"] for i in data["items"]}
        assert "inc_1" in ids
        assert "inc_2" not in ids
        assert "inc_3" not in ids

    def test_filter_since_early_includes_all(self, client):
        res = client.get("/v1/incidents?since=2025-01-01T00:00:00Z")
        assert res.status_code == 200
        assert res.json()["total"] == 3

    def test_no_filter_returns_all(self, client):
        res = client.get("/v1/incidents")
        assert res.status_code == 200
        assert res.json()["total"] == 3

    def test_combined_filters_narrow_results(self, client):
        res = client.get("/v1/incidents?status=new&level=HIGH")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert data["items"][0]["incident_id"] == "inc_1"

    def test_filter_yields_empty_when_no_match(self, client):
        res = client.get("/v1/incidents?status=escalated")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 0
        assert data["items"] == []


# ===========================================================================
# 2. GET /v1/incidents — Sorting
# ===========================================================================


class TestIncidentSorting:
    """sort=risk and sort=last_seen produce correct descending order."""

    def test_sort_risk_descending(self, client):
        """risk_score DESC: 90 → 60 → 30."""
        res = client.get("/v1/incidents?sort=risk")
        assert res.status_code == 200
        ids = [i["incident_id"] for i in res.json()["items"]]
        assert ids == ["inc_1", "inc_2", "inc_3"]

    def test_sort_last_seen_descending(self, client):
        """last_seen DESC: Oct 2026 → Feb 2026 → Jan 2026."""
        res = client.get("/v1/incidents?sort=last_seen")
        assert res.status_code == 200
        ids = [i["incident_id"] for i in res.json()["items"]]
        assert ids == ["inc_1", "inc_3", "inc_2"]

    def test_default_sort_equals_risk(self, client):
        """Omitting sort= defaults to risk_score DESC."""
        res_default = client.get("/v1/incidents").json()["items"]
        res_risk = client.get("/v1/incidents?sort=risk").json()["items"]
        assert [i["incident_id"] for i in res_default] == [i["incident_id"] for i in res_risk]

    def test_unknown_sort_falls_back_to_risk(self, client):
        """Unrecognised sort key falls back to risk_score DESC."""
        res = client.get("/v1/incidents?sort=bogus")
        assert res.status_code == 200
        ids = [i["incident_id"] for i in res.json()["items"]]
        assert ids == ["inc_1", "inc_2", "inc_3"]


# ===========================================================================
# 3. GET /v1/incidents — Pagination
# ===========================================================================


class TestIncidentPagination:
    """limit and offset slice results; total always reflects full count."""

    def test_limit_1_returns_one_item(self, client):
        res = client.get("/v1/incidents?limit=1&sort=risk")
        data = res.json()
        assert len(data["items"]) == 1
        assert data["total"] == 3
        assert data["items"][0]["incident_id"] == "inc_1"

    def test_offset_1_skips_first(self, client):
        res = client.get("/v1/incidents?limit=1&offset=1&sort=risk")
        data = res.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["incident_id"] == "inc_2"

    def test_offset_beyond_total_returns_empty(self, client):
        res = client.get("/v1/incidents?offset=100")
        data = res.json()
        assert data["items"] == []
        assert data["total"] == 3

    def test_pagination_metadata_echoed(self, client):
        res = client.get("/v1/incidents?limit=2&offset=1")
        data = res.json()
        assert data["limit"] == 2
        assert data["offset"] == 1

    def test_two_pages_cover_all_incidents(self, client):
        page1 = client.get("/v1/incidents?limit=2&offset=0&sort=risk").json()
        page2 = client.get("/v1/incidents?limit=2&offset=2&sort=risk").json()
        all_ids = sorted(
            [i["incident_id"] for i in page1["items"]]
            + [i["incident_id"] for i in page2["items"]]
        )
        assert all_ids == ["inc_1", "inc_2", "inc_3"]


# ===========================================================================
# 4. GET /v1/incidents/{id} — Detail Retrieval
# ===========================================================================


class TestIncidentDetail:
    """Detail endpoint returns full incident with flows, actions, top_features."""

    def test_valid_incident_returns_200(self, client):
        assert client.get("/v1/incidents/inc_1").status_code == 200

    def test_correct_incident_id_in_response(self, client):
        data = client.get("/v1/incidents/inc_1").json()
        assert data["incident_id"] == "inc_1"

    def test_sample_flow_ids_populated(self, client):
        data = client.get("/v1/incidents/inc_1").json()
        assert set(data["sample_flow_ids"]) == {"f1", "f2"}

    def test_sample_flow_ids_empty_when_no_flows(self, client):
        data = client.get("/v1/incidents/inc_2").json()
        assert data["sample_flow_ids"] == []

    def test_top_features_deserialized(self, client):
        data = client.get("/v1/incidents/inc_1").json()
        assert isinstance(data["top_features"], list)
        assert len(data["top_features"]) == 1
        feat = data["top_features"][0]
        assert feat["feature"] == "f1"
        assert feat["shap_value"] == pytest.approx(0.5)

    def test_top_features_empty_list_when_no_features(self, client):
        data = client.get("/v1/incidents/inc_2").json()
        assert data["top_features"] == []

    def test_actions_populated_for_inc2(self, client):
        data = client.get("/v1/incidents/inc_2").json()
        assert len(data["actions"]) == 1
        assert data["actions"][0]["analyst"] == "Alice"
        assert data["actions"][0]["action"] == "acknowledge"

    def test_actions_empty_for_fresh_incident(self, client):
        data = client.get("/v1/incidents/inc_1").json()
        assert data["actions"] == []

    def test_nonexistent_incident_returns_404(self, client):
        assert client.get("/v1/incidents/does_not_exist").status_code == 404

    def test_404_detail_message(self, client):
        res = client.get("/v1/incidents/ghost_xyz")
        assert "not found" in res.json()["detail"].lower()


# ===========================================================================
# 5. POST /v1/incidents/{id}/actions — X-Analyst header enforcement
# ===========================================================================


class TestActionHeaderEnforcement:
    """X-Analyst header is mandatory and must be 'Name + Role'; absence, empty or a bare name yields 422."""

    def test_missing_header_returns_422(self, client):
        res = client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "acknowledge"},
        )
        assert res.status_code == 422

    def test_empty_header_returns_422(self, client):
        res = client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "acknowledge"},
            headers={"X-Analyst": ""},
        )
        assert res.status_code == 422

    def test_valid_header_passes(self, client):
        res = client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "acknowledge"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        assert res.status_code == 200

    def test_response_contains_analyst_name(self, client):
        res = client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "acknowledge"},
            headers={"X-Analyst": "Charlie + Analyst"},
        )
        assert res.status_code == 200
        assert res.json()["analyst"] == "Charlie + Analyst"


# ===========================================================================
# 6. POST /v1/incidents/{id}/actions — Valid status transitions
# ===========================================================================


class TestActionStatusTransitions:
    """Each action verb maps to the correct new incident status."""

    def test_acknowledge_sets_acknowledged(self, client):
        res = client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "acknowledge"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        assert res.status_code == 200
        assert res.json()["action"] == "acknowledge"
        assert _inc_row("inc_1")["status"] == "acknowledged"

    def test_escalate_sets_escalated(self, client):
        client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "escalate"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        assert _inc_row("inc_1")["status"] == "escalated"

    def test_dismiss_fp_sets_dismissed_fp(self, client):
        client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "dismiss_fp"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        assert _inc_row("inc_1")["status"] == "dismissed_fp"

    def test_resolve_sets_resolved(self, client):
        client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "resolve"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        assert _inc_row("inc_1")["status"] == "resolved"

    def test_action_response_schema(self, client):
        """Response must include action_id, incident_id, analyst, action, at."""
        res = client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "acknowledge", "note": "test"},
            headers={"X-Analyst": "Dave + Analyst"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["incident_id"] == "inc_1"
        assert data["action"] == "acknowledge"
        assert "action_id" in data
        assert "at" in data


# ===========================================================================
# 7. POST /v1/incidents/{id}/actions — Terminal-state blocking
# ===========================================================================


class TestTerminalStateBlocking:
    """Actions on closed incidents (dismissed_fp / resolved) must return 400."""

    def test_action_on_resolved_returns_400(self, client):
        res = client.post(
            "/v1/incidents/inc_3/actions",
            json={"action": "acknowledge"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        assert res.status_code == 400

    def test_400_detail_contains_closed(self, client):
        res = client.post(
            "/v1/incidents/inc_3/actions",
            json={"action": "escalate"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        assert "closed" in res.json()["detail"].lower()

    def test_action_on_dismissed_fp_returns_400(self, client):
        """Dismiss inc_1, then any further action must return 400."""
        r1 = client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "dismiss_fp"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        assert r1.status_code == 200

        r2 = client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "acknowledge"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        assert r2.status_code == 400

    def test_action_on_nonexistent_incident_returns_404(self, client):
        res = client.post(
            "/v1/incidents/ghost_inc/actions",
            json={"action": "acknowledge"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        assert res.status_code == 404


# ===========================================================================
# 8. POST /v1/incidents/{id}/actions — MTTA timestamp logic
# ===========================================================================


class TestMTTATimestamp:
    """acknowledged_at is stamped only on the first acknowledge from 'new'."""

    def test_acknowledged_at_set_on_first_ack_from_new(self, client):
        client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "acknowledge"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        assert _inc_row("inc_1")["acknowledged_at"] is not None

    def test_acknowledged_at_immutable_after_first_ack(self, client):
        """Two sequential actions: ack then escalate. acknowledged_at must not change."""
        client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "acknowledge"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        ack_ts = _inc_row("inc_1")["acknowledged_at"]
        assert ack_ts is not None

        client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "escalate"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        assert _inc_row("inc_1")["acknowledged_at"] == ack_ts

    def test_acknowledged_at_not_overwritten_for_non_new_status(self, client):
        """inc_2 is already 'acknowledged'. Escalating must not touch acknowledged_at."""
        before = _inc_row("inc_2")["acknowledged_at"]
        client.post(
            "/v1/incidents/inc_2/actions",
            json={"action": "escalate"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        assert _inc_row("inc_2")["acknowledged_at"] == before

    def test_acknowledged_at_not_set_for_non_acknowledge_action(self, client):
        """Escalating a 'new' incident must NOT set acknowledged_at."""
        client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "escalate"},
            headers={"X-Analyst": "Bob + Analyst"},
        )
        assert _inc_row("inc_1")["acknowledged_at"] is None


# ===========================================================================
# 9. POST /v1/incidents/{id}/actions — Audit log insertion
# ===========================================================================


class TestAuditLogInsertion:
    """Every successful action inserts a row in analyst_actions."""

    def test_audit_row_created(self, client):
        client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "acknowledge", "note": "checking"},
            headers={"X-Analyst": "Eve + Analyst"},
        )
        rows = _audit_rows("inc_1")
        assert len(rows) == 1
        assert rows[0]["analyst"] == "Eve + Analyst"
        assert rows[0]["action"] == "acknowledge"
        assert rows[0]["note"] == "checking"

    def test_multiple_actions_all_logged(self, client):
        for action in ("acknowledge", "escalate"):
            client.post(
                "/v1/incidents/inc_1/actions",
                json={"action": action},
                headers={"X-Analyst": "Frank + Analyst"},
            )
        rows = _audit_rows("inc_1")
        assert [r["action"] for r in rows] == ["acknowledge", "escalate"]

    def test_audit_row_has_timestamp(self, client):
        client.post(
            "/v1/incidents/inc_1/actions",
            json={"action": "resolve"},
            headers={"X-Analyst": "Grace + Analyst"},
        )
        rows = _audit_rows("inc_1")
        assert len(rows) == 1
        assert rows[0]["at"] is not None

    def test_blocked_action_does_not_create_audit_row(self, client):
        """A 400-rejected action on a closed incident must NOT insert an audit row."""
        before = len(_audit_rows("inc_3"))
        client.post(
            "/v1/incidents/inc_3/actions",
            json={"action": "acknowledge"},
            headers={"X-Analyst": "Hank + Analyst"},
        )
        assert len(_audit_rows("inc_3")) == before
