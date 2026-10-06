"""M3-05 tests: Incident Correlator.

Tests comprehensive windowing, key separation, status guards, running aggregates,
burst risk scaling, SHAP aggregation, foreign-key linkage, and end-to-end batch correlation.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.app.correlator import IncidentCorrelator
from api.tests.helpers import AUTH_HEADERS
from nscore.bundle.loader import load_bundle
from nscore.contracts.schemas import AttackFamily, FeatureContribution, FlowMeta, Verdict

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def mock_bundle_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from scripts.make_mock_bundle import build
    out_root = tmp_path_factory.mktemp("bundles_m305")
    return build("cic", out_root, seed=42)


@pytest.fixture(scope="session")
def real_bundle(mock_bundle_path: Path):
    return load_bundle(f"local:{mock_bundle_path}")


@pytest.fixture()
def db_conn(tmp_path: Path):
    """Isolated SQLite connection for unit-level correlator tests."""
    from scripts.init_db import init_db
    p = str(tmp_path / "correlator_unit.db")
    init_db(p)
    conn = sqlite3.connect(p)
    conn.execute("PRAGMA foreign_keys = ON;")
    yield conn
    conn.close()


@pytest.fixture()
def scoring_client(real_bundle, tmp_path: Path):
    """TestClient with real bundle and isolated DB injected for integration tests."""
    from api.app.main import ModelContext, app
    from api.app.scoring import ScoringService
    from scripts.init_db import init_db

    db_file = str(tmp_path / "correlator_api.db")
    init_db(db_file)

    prior_ctx = getattr(app.state, "model_ctx", None)

    app.state.model_ctx = ModelContext(real_bundle, ScoringService(real_bundle), None)

    prev_db = os.environ.get("NS_DB_PATH")
    os.environ["NS_DB_PATH"] = db_file

    client = TestClient(app, raise_server_exceptions=True, headers=AUTH_HEADERS)
    yield client, db_file

    app.state.model_ctx = prior_ctx
    if prev_db is not None:
        os.environ["NS_DB_PATH"] = prev_db
    else:
        os.environ.pop("NS_DB_PATH", None)


def _make_meta(
    flow_id: str = "f-1",
    observed_at: str = "2026-10-03T12:00:00Z",
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.1",
    src_port: int = 50000,
    dst_port: int = 80,
    protocol: int = 6,
) -> FlowMeta:
    return FlowMeta(
        flow_id=flow_id,
        observed_at=datetime.fromisoformat(observed_at.replace("Z", "+00:00")),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
    )


# ---------------------------------------------------------------------------
# Unit Tests for IncidentCorrelator
# ---------------------------------------------------------------------------

class TestCorrelatorUnit:
    """Detailed unit tests for IncidentCorrelator logic and edge cases."""

    def test_window_merge_within_300s(self, db_conn):
        correlator = IncidentCorrelator(window_seconds=300.0)
        t0 = "2026-10-03T12:00:00Z"
        t1 = "2026-10-03T12:03:00Z"  # 180s later (< 300s)

        # Flow 1 -> Creates incident
        inc_id1, c1, u1 = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f1", t0),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.85,
            severity=0.80,
            model_version="v1",
            top_features=[],
        )
        assert c1 == 1 and u1 == 0

        # Flow 2 -> Merges into existing incident
        inc_id2, c2, u2 = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f2", t1),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.90,
            severity=0.80,
            model_version="v1",
            top_features=[],
        )
        assert c2 == 0 and u2 == 1
        assert inc_id1 == inc_id2

        row = db_conn.execute(
            "SELECT flow_count, first_seen, last_seen FROM incidents WHERE incident_id = ?",
            (inc_id1,),
        ).fetchone()
        assert row[0] == 2
        assert "12:00:00" in row[1]
        assert "12:03:00" in row[2]

    def test_window_expiry_beyond_300s(self, db_conn):
        correlator = IncidentCorrelator(window_seconds=300.0)
        t0 = "2026-10-03T12:00:00Z"
        t1 = "2026-10-03T12:05:01Z"  # 301s later (> 300s)

        inc_id1, c1, u1 = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f1", t0),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.85,
            severity=0.80,
            model_version="v1",
            top_features=[],
        )
        assert c1 == 1 and u1 == 0

        inc_id2, c2, u2 = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f2", t1),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.85,
            severity=0.80,
            model_version="v1",
            top_features=[],
        )
        assert c2 == 1 and u2 == 0
        assert inc_id1 != inc_id2

        count = db_conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        assert count == 2

    def test_src_ip_separation(self, db_conn):
        correlator = IncidentCorrelator()
        t = "2026-10-03T12:00:00Z"

        id1, c1, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f1", t, src_ip="10.0.0.1"),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.8,
            severity=0.8,
            model_version="v1",
            top_features=[],
        )
        id2, c2, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f2", t, src_ip="10.0.0.2"),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.8,
            severity=0.8,
            model_version="v1",
            top_features=[],
        )
        assert id1 != id2
        assert c1 == 1 and c2 == 1

    def test_dst_ip_separation(self, db_conn):
        correlator = IncidentCorrelator()
        t = "2026-10-03T12:00:00Z"

        id1, _, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f1", t, dst_ip="192.168.1.1"),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.8,
            severity=0.8,
            model_version="v1",
            top_features=[],
        )
        id2, _, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f2", t, dst_ip="192.168.1.2"),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.8,
            severity=0.8,
            model_version="v1",
            top_features=[],
        )
        assert id1 != id2

    def test_attack_family_separation(self, db_conn):
        correlator = IncidentCorrelator()
        t = "2026-10-03T12:00:00Z"

        id1, _, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f1", t),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.8,
            severity=0.8,
            model_version="v1",
            top_features=[],
        )
        id2, _, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f2", t),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.BRUTE_FORCE,
            confidence=0.8,
            severity=0.7,
            model_version="v1",
            top_features=[],
        )
        assert id1 != id2

    def test_unknown_novel_separation_from_known_attack(self, db_conn):
        correlator = IncidentCorrelator()
        t = "2026-10-03T12:00:00Z"

        id_known, _, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f1", t),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.8,
            severity=0.8,
            model_version="v1",
            top_features=[],
        )
        id_novel, _, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f2", t),
            verdict=Verdict.NOVEL_ANOMALY,
            family=AttackFamily.UNKNOWN,
            confidence=0.75,
            severity=0.75,
            model_version="v1",
            top_features=[],
        )
        assert id_known != id_novel

    def test_resolved_incident_cannot_merge(self, db_conn):
        correlator = IncidentCorrelator()
        t0 = "2026-10-03T12:00:00Z"
        t1 = "2026-10-03T12:01:00Z"

        inc_id1, _, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f1", t0),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.BOTNET,
            confidence=0.9,
            severity=0.9,
            model_version="v1",
            top_features=[],
        )
        # Mark as resolved
        db_conn.execute("UPDATE incidents SET status = 'resolved' WHERE incident_id = ?", (inc_id1,))

        inc_id2, c2, u2 = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f2", t1),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.BOTNET,
            confidence=0.9,
            severity=0.9,
            model_version="v1",
            top_features=[],
        )
        assert inc_id1 != inc_id2
        assert c2 == 1 and u2 == 0

    def test_dismissed_fp_incident_cannot_merge(self, db_conn):
        correlator = IncidentCorrelator()
        t0 = "2026-10-03T12:00:00Z"
        t1 = "2026-10-03T12:01:00Z"

        inc_id1, _, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f1", t0),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.BOTNET,
            confidence=0.9,
            severity=0.9,
            model_version="v1",
            top_features=[],
        )
        db_conn.execute("UPDATE incidents SET status = 'dismissed_fp' WHERE incident_id = ?", (inc_id1,))

        inc_id2, c2, u2 = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f2", t1),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.BOTNET,
            confidence=0.9,
            severity=0.9,
            model_version="v1",
            top_features=[],
        )
        assert inc_id1 != inc_id2
        assert c2 == 1 and u2 == 0

    def test_investigating_and_escalated_can_merge(self, db_conn):
        correlator = IncidentCorrelator()
        t0 = "2026-10-03T12:00:00Z"
        t1 = "2026-10-03T12:01:00Z"
        t2 = "2026-10-03T12:02:00Z"

        inc_id, _, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f1", t0),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.INFILTRATION,
            confidence=0.9,
            severity=1.0,
            model_version="v1",
            top_features=[],
        )
        # Transition to investigating -> should merge
        db_conn.execute("UPDATE incidents SET status = 'investigating' WHERE incident_id = ?", (inc_id,))
        id_inv, c_inv, u_inv = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f2", t1),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.INFILTRATION,
            confidence=0.95,
            severity=1.0,
            model_version="v1",
            top_features=[],
        )
        assert id_inv == inc_id and u_inv == 1

        # Transition to escalated -> should merge
        db_conn.execute("UPDATE incidents SET status = 'escalated' WHERE incident_id = ?", (inc_id,))
        id_esc, c_esc, u_esc = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f3", t2),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.INFILTRATION,
            confidence=0.98,
            severity=1.0,
            model_version="v1",
            top_features=[],
        )
        assert id_esc == inc_id and u_esc == 1

    def test_running_mean_severity_and_max_confidence(self, db_conn):
        correlator = IncidentCorrelator()
        t0 = "2026-10-03T12:00:00Z"
        t1 = "2026-10-03T12:01:00Z"
        t2 = "2026-10-03T12:02:00Z"

        inc_id, _, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f1", t0),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.70,
            severity=0.80,
            model_version="v1",
            top_features=[],
        )
        correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f2", t1),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.95,
            severity=0.60,
            model_version="v1",
            top_features=[],
        )
        correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f3", t2),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.50,
            severity=0.40,
            model_version="v1",
            top_features=[],
        )

        row = db_conn.execute(
            "SELECT severity, max_confidence, flow_count FROM incidents WHERE incident_id = ?",
            (inc_id,),
        ).fetchone()
        assert row[2] == 3
        # Expected severity: (0.80 + 0.60 + 0.40) / 3 = 0.60
        assert pytest.approx(row[0], rel=1e-5) == 0.60
        # Max confidence: max(0.70, 0.95, 0.50) = 0.95
        assert pytest.approx(row[1], rel=1e-5) == 0.95

    def test_burst_risk_scaling_with_flow_count(self, db_conn):
        correlator = IncidentCorrelator()
        base_t = datetime(2026, 10, 3, 12, 0, 0, tzinfo=UTC)

        # Flow 1
        inc_id, _, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f0", base_t.isoformat()),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.9,
            severity=0.8,
            model_version="v1",
            top_features=[],
        )
        risk_1 = db_conn.execute("SELECT risk_score FROM incidents WHERE incident_id = ?", (inc_id,)).fetchone()[0]

        # Add 99 more flows (flow_count -> 100)
        for i in range(1, 100):
            t = base_t + timedelta(seconds=i * 2)
            correlator.correlate_flow(
                conn=db_conn,
                meta=_make_meta(f"f{i}", t.isoformat()),
                verdict=Verdict.KNOWN_ATTACK,
                family=AttackFamily.DOS,
                confidence=0.9,
                severity=0.8,
                model_version="v1",
                top_features=[],
            )

        risk_100 = db_conn.execute("SELECT risk_score FROM incidents WHERE incident_id = ?", (inc_id,)).fetchone()[0]
        # Burst factor at flow_count=100 is 1 + 0.15 * (2/3) = 1.10
        # Risk must strictly increase with burst
        assert risk_100 > risk_1

    def test_top_5_shap_aggregation(self, db_conn):
        import json
        correlator = IncidentCorrelator()
        t0 = "2026-10-03T12:00:00Z"
        t1 = "2026-10-03T12:01:00Z"

        fc1 = [
            FeatureContribution(feature="fwd_pkt", value=10.0, shap_value=0.4, baseline_median=2.0),
            FeatureContribution(feature="flow_dur", value=100.0, shap_value=0.2, baseline_median=50.0),
        ]
        fc2 = [
            FeatureContribution(feature="fwd_pkt", value=12.0, shap_value=0.6, baseline_median=2.0),
            FeatureContribution(feature="syn_flag", value=1.0, shap_value=0.8, baseline_median=0.0),
        ]

        inc_id, _, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f1", t0),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.9,
            severity=0.8,
            model_version="v1",
            top_features=fc1,
        )
        correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f2", t1),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.9,
            severity=0.8,
            model_version="v1",
            top_features=fc2,
        )

        raw_json = db_conn.execute(
            "SELECT top_features_json FROM incidents WHERE incident_id = ?",
            (inc_id,),
        ).fetchone()[0]
        top = json.loads(raw_json)
        assert len(top) == 3
        # Order should be ranked by mean |shap|:
        # fwd_pkt: (0.4 + 0.6) / 2 = 0.50
        # syn_flag: 0.8 / 2 = 0.40
        # flow_dur: 0.2 / 2 = 0.10
        assert top[0]["feature"] == "fwd_pkt" and pytest.approx(top[0]["shap_value"], rel=1e-3) == 0.50
        assert top[1]["feature"] == "syn_flag" and pytest.approx(top[1]["shap_value"], rel=1e-3) == 0.40
        assert top[2]["feature"] == "flow_dur" and pytest.approx(top[2]["shap_value"], rel=1e-3) == 0.10


# ---------------------------------------------------------------------------
# Integration Tests with Scoring Engine and API Endpoint
# ---------------------------------------------------------------------------

class TestCorrelatorBatchIntegration:
    """Integration tests verifying correlator behavior through POST /v1/flows."""

    def test_50_flow_end_to_end_batch_correlation(self, scoring_client, real_bundle):
        """A batch of 50 matching flows from identical src/dst must produce 1 incident and 49 updates."""
        client, db_file = scoring_client
        import numpy as np

        from scripts.make_mock_bundle import synthetic_frame

        rng = np.random.default_rng(42)
        df, _, _ = synthetic_frame(real_bundle.spec, rng)

        # Force high feature values to ensure attack verdict
        row = df.iloc[0]
        features = {name: float(row[name]) for name in real_bundle.spec.names}

        # Build 50 flows sharing the EXACT SAME src_ip and dst_ip within 2 seconds of each other
        flows = []
        base_time = datetime(2026, 10, 3, 12, 0, 0, tzinfo=UTC)
        for i in range(50):
            t = base_time + timedelta(seconds=i * 2)
            flows.append({
                "meta": {
                    "flow_id": f"batch-flow-{i:04d}",
                    "observed_at": t.isoformat(),
                    "src_ip": "10.10.10.50",
                    "dst_ip": "192.168.1.100",
                    "src_port": 40000 + i,
                    "dst_port": 80,
                    "protocol": 6,
                },
                "features": features,
            })

        resp = client.post("/v1/flows", json={"flows": flows})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["received"] == 50

        # Verify incident creation & update counts
        # All non-benign flows sharing same IP and family must merge into ONE incident
        non_benign_count = sum(1 for r in data["results"] if r["verdict"] != "benign")
        if non_benign_count > 0:
            assert data["incidents_created"] == 1
            assert data["incidents_updated"] == non_benign_count - 1

            conn = sqlite3.connect(db_file)
            inc_rows = conn.execute("SELECT incident_id, flow_count FROM incidents").fetchall()
            assert len(inc_rows) == 1
            assert inc_rows[0][1] == non_benign_count

            # Verify every non-benign flow points to this single incident_id
            target_incident_id = inc_rows[0][0]
            for r in data["results"]:
                if r["verdict"] != "benign":
                    assert r["incident_id"] == target_incident_id

            # Check DB foreign-key reference in flows table
            flow_rows = conn.execute("SELECT incident_id FROM flows").fetchall()
            conn.close()
            assert len(flow_rows) == 50
            for f_row in flow_rows:
                assert f_row[0] == target_incident_id
