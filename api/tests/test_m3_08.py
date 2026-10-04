"""M3-08 tests: Drift Monitor Service & Live Metrics.

Covers:
  DriftMonitor unit tests:
    - rolling window caps at WINDOW_SIZE (2,000)
    - no snapshot generated below SNAPSHOT_INTERVAL (500)
    - snapshot triggered at exactly 500 flows
    - second snapshot triggered at 1,000 flows
    - report schema is valid after compute
  DriftMonitor DB persistence:
    - snapshot row written with correct columns
    - report_json deserializes to DriftReport
  GET /v1/drift:
    - 404 when no snapshot exists
    - 200 with valid DriftReport after snapshot exists
    - mock mode preserved
  GET /v1/metrics:
    - empty DB returns zeroes / None
    - flows_scored_total accurate
    - latency p50/p95 computed correctly
    - incidents_open and by_level accurate
    - analyst_confirmed_precision / fp_dismiss_rate accurate
    - mtta_seconds accurate
    - mock mode preserved
  Integration:
    - observe() + _compute_and_persist() round-trip via DriftMonitor directly
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from api.app.db import db_session, get_connection
from api.app.main import app
from nscore.bundle.loader import load_bundle
from nscore.contracts import schemas
from scripts.init_db import init_db

# ---------------------------------------------------------------------------
# Session-scoped bundle (built once for all M3-08 tests)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def mock_bundle_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from scripts.make_mock_bundle import build

    out_root = tmp_path_factory.mktemp("bundles_m308")
    return build("cic", out_root, seed=99)


@pytest.fixture(scope="session")
def real_bundle(mock_bundle_path: Path):
    return load_bundle(f"local:{mock_bundle_path}")


# ---------------------------------------------------------------------------
# Per-test isolated DB
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_path(tmp_path: Path) -> str:
    p = str(tmp_path / "test_m308.db")
    init_db(p)
    return p


# ---------------------------------------------------------------------------
# DriftMonitor fixture (unit tests - no HTTP)
# ---------------------------------------------------------------------------


@pytest.fixture()
def monitor(real_bundle, db_path: str):
    """Freshly constructed DriftMonitor with isolated DB."""
    from api.app.services.drift import DriftMonitor

    return DriftMonitor(real_bundle, db_path)


# ---------------------------------------------------------------------------
# API client fixture for drift / metrics endpoint tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def drift_client(real_bundle, db_path: str):
    """
    TestClient backed by real bundle + isolated DB + DriftMonitor.
    Injects state directly (no lifespan) to avoid bundle-load side-effects.
    """
    from api.app.scoring import ScoringService
    from api.app.services.drift import DriftMonitor

    prior_bundle = getattr(app.state, "bundle", None)
    prior_scorer = getattr(app.state, "scorer", None)
    prior_monitor = getattr(app.state, "drift_monitor", None)

    dm = DriftMonitor(real_bundle, db_path)
    app.state.bundle = real_bundle
    app.state.scorer = ScoringService(real_bundle)
    app.state.drift_monitor = dm

    prev_db = os.environ.get("NS_DB_PATH")
    os.environ["NS_DB_PATH"] = db_path
    os.environ.pop("NS_MOCK", None)

    client = TestClient(app, raise_server_exceptions=True)
    yield client, dm, db_path

    app.state.bundle = prior_bundle
    app.state.scorer = prior_scorer
    app.state.drift_monitor = prior_monitor
    if prev_db is not None:
        os.environ["NS_DB_PATH"] = prev_db
    else:
        os.environ.pop("NS_DB_PATH", None)


# ---------------------------------------------------------------------------
# Helper: seed flows / incidents / actions for metrics tests
# ---------------------------------------------------------------------------


def _seed_metrics_data(db_path: str) -> None:
    """Insert known data so we can assert exact metrics values."""
    # now_iso = datetime.now(UTC).isoformat()
    one_min_ago = (datetime.now(UTC) - timedelta(seconds=50)).isoformat()
    two_min_ago = (datetime.now(UTC) - timedelta(seconds=120)).isoformat()

    with get_connection(db_path) as conn:
        # 3 flows: 2 recent (within 60s), 1 old. Latencies: 10, 20, 30 ms.
        conn.executescript(f"""
            INSERT INTO flows (flow_id, observed_at, received_at, src_ip, dst_ip,
                               src_port, dst_port, protocol, features_json,
                               verdict, p_attack, anomaly_pct, attack_family,
                               severity, model_version, latency_ms)
            VALUES
            ('f1','2026-01-01T00:00:00Z','{one_min_ago}','1.1.1.1','2.2.2.2',
             1000,80,6,'{{}}','known_attack',0.9,50,'DoS',0.8,'v1',10.0),
            ('f2','2026-01-01T00:00:01Z','{one_min_ago}','1.1.1.1','2.2.2.2',
             1001,80,6,'{{}}','benign',0.1,5,'BENIGN',0.0,'v1',20.0),
            ('f3','2026-01-01T00:00:02Z','{two_min_ago}','3.3.3.3','4.4.4.4',
             2000,443,6,'{{}}','known_attack',0.8,40,'DoS',0.7,'v1',30.0);

            INSERT INTO incidents (incident_id, status, verdict, attack_family,
                                   risk_score, risk_level, severity, max_confidence,
                                   flow_count, src_ip, dst_ip, dst_port,
                                   first_seen, last_seen, model_version,
                                   acknowledged_at)
            VALUES
            ('inc_open1','new','known_attack','DoS',
             80,'HIGH',0.8,0.9,1,'1.1.1.1','2.2.2.2',80,
             '2026-01-01T00:00:00Z','2026-01-01T00:01:00Z','v1',NULL),
            ('inc_open2','acknowledged','known_attack','DoS',
             50,'MEDIUM',0.5,0.7,1,'3.3.3.3','4.4.4.4',443,
             '2026-01-01T00:00:00Z','2026-01-01T00:02:00Z','v1',
             '2026-01-01T00:01:00Z'),
            ('inc_closed','resolved','known_attack','DoS',
             30,'LOW',0.3,0.6,1,'5.5.5.5','6.6.6.6',8080,
             '2026-01-01T00:00:00Z','2026-01-01T00:00:30Z','v1',NULL);

            INSERT INTO analyst_actions (incident_id, analyst, action, note, at)
            VALUES
            ('inc_open2','Alice','confirm','TP','2026-01-01T00:01:30Z'),
            ('inc_closed','Bob','dismiss_fp','FP','2026-01-01T00:01:00Z');
        """)
        conn.commit()


# ===========================================================================
# TestDriftMonitorUnit
# ===========================================================================


class TestDriftMonitorUnit:
    """Unit tests for DriftMonitor rolling window and trigger logic."""

    def test_report_none_initially(self, monitor):
        assert monitor.get_latest_report() is None

    def test_below_threshold_no_snapshot(self, monitor):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(499, n_feat))
        assert monitor.get_latest_report() is None

    def test_exactly_500_triggers_snapshot(self, monitor):
        n_feat = len(monitor._names)
        # 499 → no trigger
        monitor.observe(np.random.rand(499, n_feat))
        assert monitor.get_latest_report() is None
        # +1 → checkpoint crossed → trigger
        monitor.observe(np.random.rand(1, n_feat))
        report = monitor.get_latest_report()
        assert report is not None
        assert isinstance(report, schemas.DriftReport)

    def test_window_caps_at_2000(self, monitor):
        from api.app.services.drift import WINDOW_SIZE

        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(2500, n_feat))
        assert len(monitor._deque) == WINDOW_SIZE

    def test_1000_flows_two_snapshots(self, monitor, db_path: str):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(500, n_feat))
        with db_session(db_path) as conn:
            count1 = conn.execute(
                "SELECT COUNT(*) FROM drift_snapshots"
            ).fetchone()[0]
        assert count1 == 1

        monitor.observe(np.random.rand(500, n_feat))
        with db_session(db_path) as conn:
            count2 = conn.execute(
                "SELECT COUNT(*) FROM drift_snapshots"
            ).fetchone()[0]
        assert count2 == 2

    def test_single_row_no_trigger(self, monitor):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(1, n_feat))
        assert monitor.get_latest_report() is None
        assert monitor._total_observed == 1

    def test_total_observed_tracks_cumulative(self, monitor):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(200, n_feat))
        monitor.observe(np.random.rand(150, n_feat))
        assert monitor._total_observed == 350

    def test_empty_array_ignored(self, monitor):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(0, n_feat))
        assert monitor._total_observed == 0

    def test_verdict_deque_tracks_attack_rate(self, monitor):
        n_feat = len(monitor._names)
        X = np.random.rand(500, n_feat)
        verdicts = ["known_attack"] * 100 + ["benign"] * 400
        monitor.observe(X, verdicts)
        report = monitor.get_latest_report()
        assert report is not None
        # 100/500 = 0.2
        assert abs(report.prediction_attack_rate - 0.2) < 1e-6

    def test_report_schema_valid(self, monitor):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(500, n_feat))
        report = monitor.get_latest_report()
        assert report is not None
        # Ensure Pydantic round-trip works
        raw = report.model_dump(mode="json")
        rebuilt = schemas.DriftReport.model_validate(raw)
        assert rebuilt.max_psi == report.max_psi

    def test_status_enum_valid(self, monitor):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(500, n_feat))
        report = monitor.get_latest_report()
        assert report is not None
        assert report.status in (
            schemas.DriftStatus.OK,
            schemas.DriftStatus.WATCH,
            schemas.DriftStatus.ALERT,
        )

    def test_window_size_in_report(self, monitor):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(500, n_feat))
        report = monitor.get_latest_report()
        assert report is not None
        assert report.window_size == 500

    def test_features_list_non_empty(self, monitor):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(500, n_feat))
        report = monitor.get_latest_report()
        assert report is not None
        assert len(report.features) > 0
        for fd in report.features:
            assert isinstance(fd, schemas.FeatureDrift)
            assert fd.psi >= 0


# ===========================================================================
# TestDriftMonitorSnapshot  — DB persistence
# ===========================================================================


class TestDriftMonitorSnapshot:
    """Verify that snapshots are correctly persisted to the drift_snapshots table."""

    def test_snapshot_row_created(self, monitor, db_path: str):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(500, n_feat))
        with db_session(db_path) as conn:
            row = conn.execute(
                "SELECT * FROM drift_snapshots ORDER BY id DESC LIMIT 1"
            ).fetchone()
        assert row is not None

    def test_snapshot_model_version_correct(self, monitor, db_path: str, real_bundle):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(500, n_feat))
        with db_session(db_path) as conn:
            row = dict(
                conn.execute(
                    "SELECT * FROM drift_snapshots ORDER BY id DESC LIMIT 1"
                ).fetchone()
            )
        assert row["model_version"] == real_bundle.version

    def test_snapshot_window_size_correct(self, monitor, db_path: str):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(500, n_feat))
        with db_session(db_path) as conn:
            row = dict(
                conn.execute(
                    "SELECT window_size FROM drift_snapshots ORDER BY id DESC LIMIT 1"
                ).fetchone()
            )
        assert row["window_size"] == 500

    def test_snapshot_max_psi_non_negative(self, monitor, db_path: str):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(500, n_feat))
        with db_session(db_path) as conn:
            row = dict(
                conn.execute(
                    "SELECT max_psi FROM drift_snapshots ORDER BY id DESC LIMIT 1"
                ).fetchone()
            )
        assert row["max_psi"] >= 0.0

    def test_snapshot_report_json_deserializes(self, monitor, db_path: str):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(500, n_feat))
        with db_session(db_path) as conn:
            row = conn.execute(
                "SELECT report_json FROM drift_snapshots ORDER BY id DESC LIMIT 1"
            ).fetchone()
        assert row is not None
        report = schemas.DriftReport.model_validate_json(row[0])
        assert isinstance(report, schemas.DriftReport)

    def test_snapshot_computed_at_is_iso(self, monitor, db_path: str):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(500, n_feat))
        with db_session(db_path) as conn:
            row = dict(
                conn.execute(
                    "SELECT computed_at FROM drift_snapshots ORDER BY id DESC LIMIT 1"
                ).fetchone()
            )
        # Must be parseable as a datetime
        parsed = datetime.fromisoformat(row["computed_at"].replace("Z", "+00:00"))
        assert parsed is not None

    def test_snapshot_status_valid_string(self, monitor, db_path: str):
        n_feat = len(monitor._names)
        monitor.observe(np.random.rand(500, n_feat))
        with db_session(db_path) as conn:
            row = dict(
                conn.execute(
                    "SELECT status FROM drift_snapshots ORDER BY id DESC LIMIT 1"
                ).fetchone()
            )
        assert row["status"] in ("ok", "watch", "alert")

    def test_cold_start_loads_latest(self, real_bundle, db_path: str):
        """A second DriftMonitor constructed with the same DB recovers the latest snapshot."""
        from api.app.services.drift import DriftMonitor

        m1 = DriftMonitor(real_bundle, db_path)
        n_feat = len(m1._names)
        m1.observe(np.random.rand(500, n_feat))
        assert m1.get_latest_report() is not None

        # New instance — should load from DB
        m2 = DriftMonitor(real_bundle, db_path)
        assert m2.get_latest_report() is not None
        assert m2.get_latest_report().max_psi == m1.get_latest_report().max_psi


# ===========================================================================
# TestGetDriftEndpoint
# ===========================================================================


class TestGetDriftEndpoint:
    """GET /v1/drift real-mode endpoint tests."""

    def test_no_data_returns_404(self, drift_client):
        client, dm, _ = drift_client
        # No observe() called → no snapshot
        resp = client.get("/v1/drift")
        assert resp.status_code == 404

    def test_after_500_flows_returns_200(self, drift_client):
        client, dm, _ = drift_client
        n_feat = len(dm._names)
        dm.observe(np.random.rand(500, n_feat))
        resp = client.get("/v1/drift")
        assert resp.status_code == 200

    def test_response_schema_valid(self, drift_client):
        client, dm, _ = drift_client
        n_feat = len(dm._names)
        dm.observe(np.random.rand(500, n_feat))
        resp = client.get("/v1/drift")
        assert resp.status_code == 200
        report = schemas.DriftReport.model_validate(resp.json())
        assert report.max_psi >= 0

    def test_max_psi_in_response(self, drift_client):
        client, dm, _ = drift_client
        n_feat = len(dm._names)
        dm.observe(np.random.rand(500, n_feat))
        resp = client.get("/v1/drift")
        data = resp.json()
        assert "max_psi" in data
        assert data["max_psi"] >= 0.0

    def test_features_list_in_response(self, drift_client):
        client, dm, _ = drift_client
        n_feat = len(dm._names)
        dm.observe(np.random.rand(500, n_feat))
        resp = client.get("/v1/drift")
        data = resp.json()
        assert "features" in data
        assert len(data["features"]) > 0

    def test_window_size_in_response(self, drift_client):
        client, dm, _ = drift_client
        n_feat = len(dm._names)
        dm.observe(np.random.rand(500, n_feat))
        resp = client.get("/v1/drift")
        data = resp.json()
        assert data["window_size"] == 500

    def test_status_field_present(self, drift_client):
        client, dm, _ = drift_client
        n_feat = len(dm._names)
        dm.observe(np.random.rand(500, n_feat))
        resp = client.get("/v1/drift")
        data = resp.json()
        assert data["status"] in ("ok", "watch", "alert")


# ===========================================================================
# TestGetMetricsEndpoint
# ===========================================================================


class TestGetMetricsEndpoint:
    """GET /v1/metrics real-mode endpoint tests."""

    def test_empty_db_returns_200(self, drift_client):
        client, _, _ = drift_client
        resp = client.get("/v1/metrics")
        assert resp.status_code == 200

    def test_empty_db_schema_valid(self, drift_client):
        client, _, _ = drift_client
        resp = client.get("/v1/metrics")
        schemas.LiveMetrics.model_validate(resp.json())

    def test_empty_db_flows_total_zero(self, drift_client):
        client, _, _ = drift_client
        data = client.get("/v1/metrics").json()
        assert data["flows_scored_total"] == 0

    def test_empty_db_precision_none(self, drift_client):
        client, _, _ = drift_client
        data = client.get("/v1/metrics").json()
        assert data["analyst_confirmed_precision"] is None
        assert data["fp_dismiss_rate"] is None
        assert data["mtta_seconds"] is None

    def test_flows_scored_total_accurate(self, drift_client):
        client, _, db = drift_client
        _seed_metrics_data(db)
        data = client.get("/v1/metrics").json()
        # 3 flows seeded
        assert data["flows_scored_total"] == 3

    def test_latency_p50_p95_accurate(self, drift_client):
        client, _, db = drift_client
        _seed_metrics_data(db)
        data = client.get("/v1/metrics").json()
        # latencies: [10, 20, 30] ms → p50=20, p95≈29
        assert abs(data["latency_ms_p50"] - 20.0) < 1.0
        assert data["latency_ms_p95"] >= 25.0

    def test_incidents_open_correct(self, drift_client):
        client, _, db = drift_client
        _seed_metrics_data(db)
        data = client.get("/v1/metrics").json()
        # 2 open (new + acknowledged), 1 resolved
        assert data["incidents_open"] == 2

    def test_incidents_by_level_correct(self, drift_client):
        client, _, db = drift_client
        _seed_metrics_data(db)
        data = client.get("/v1/metrics").json()
        by_level = data["incidents_by_level"]
        # 1 HIGH (new), 1 MEDIUM (acknowledged); resolved excluded
        assert by_level["HIGH"] == 1
        assert by_level["MEDIUM"] == 1
        assert by_level["LOW"] == 0

    def test_analyst_precision_accurate(self, drift_client):
        client, _, db = drift_client
        _seed_metrics_data(db)
        data = client.get("/v1/metrics").json()
        # 1 confirm + 1 dismiss_fp → precision = 0.5, fp_rate = 0.5
        assert abs(data["analyst_confirmed_precision"] - 0.5) < 1e-6
        assert abs(data["fp_dismiss_rate"] - 0.5) < 1e-6

    def test_mtta_accurate(self, drift_client):
        client, _, db = drift_client
        _seed_metrics_data(db)
        data = client.get("/v1/metrics").json()
        # inc_open2: first_seen=00:00:00Z, acknowledged_at=00:01:00Z → 60s
        # inc_open1: no acknowledged_at → excluded
        assert data["mtta_seconds"] is not None
        assert abs(data["mtta_seconds"] - 60.0) < 1.0

    def test_flows_per_sec_non_negative(self, drift_client):
        client, _, db = drift_client
        _seed_metrics_data(db)
        data = client.get("/v1/metrics").json()
        assert data["flows_per_sec_1m"] >= 0.0

    def test_response_has_all_fields(self, drift_client):
        client, _, _ = drift_client
        data = client.get("/v1/metrics").json()
        expected_fields = {
            "flows_scored_total", "flows_per_sec_1m",
            "latency_ms_p50", "latency_ms_p95",
            "incidents_open", "incidents_by_level",
            "analyst_confirmed_precision", "fp_dismiss_rate",
            "mtta_seconds",
        }
        assert expected_fields.issubset(data.keys())


# ===========================================================================
# TestMockModePreserved  (regression: existing mock tests still pass)
# ===========================================================================


class TestMockModePreserved:
    """Ensure _is_mock() guards are still honoured for drift / metrics."""

    def test_get_drift_mock_returns_200(self):
        """NS_MOCK=1 client must return the fixture, not 404."""
        # test_mock_api.py already covers this; snapshot here for clarity
        os.environ["NS_MOCK"] = "1"
        try:
            prior_bundle = getattr(app.state, "bundle", None)
            prior_scorer = getattr(app.state, "scorer", None)
            prior_monitor = getattr(app.state, "drift_monitor", None)
            app.state.bundle = None
            app.state.scorer = None
            app.state.drift_monitor = None

            client = TestClient(app, raise_server_exceptions=True)
            resp = client.get("/v1/drift")
            assert resp.status_code == 200
            schemas.DriftReport.model_validate(resp.json())
        finally:
            os.environ.pop("NS_MOCK", None)
            app.state.bundle = prior_bundle
            app.state.scorer = prior_scorer
            app.state.drift_monitor = prior_monitor

    def test_get_metrics_mock_returns_200(self):
        """NS_MOCK=1 client must return the fixture LiveMetrics."""
        os.environ["NS_MOCK"] = "1"
        try:
            prior_bundle = getattr(app.state, "bundle", None)
            prior_scorer = getattr(app.state, "scorer", None)
            prior_monitor = getattr(app.state, "drift_monitor", None)
            app.state.bundle = None
            app.state.scorer = None
            app.state.drift_monitor = None

            client = TestClient(app, raise_server_exceptions=True)
            resp = client.get("/v1/metrics")
            assert resp.status_code == 200
            schemas.LiveMetrics.model_validate(resp.json())
        finally:
            os.environ.pop("NS_MOCK", None)
            app.state.bundle = prior_bundle
            app.state.scorer = prior_scorer
            app.state.drift_monitor = prior_monitor
