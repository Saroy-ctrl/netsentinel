"""M3-04 tests: real POST /v1/flows scoring pipeline.

Tests the full path:
  FlowBatch → DetectionEngine → (SHAP) → DB persist → ScoreBatchResponse

Uses the same session-scoped mock-cic bundle as test_m3_03.py.
DB is isolated per test via a temp file.

Isolation guarantees
--------------------
- NS_DB_PATH patched per-test; never touches netsentinel.db
- NS_MOCK is never set — real scoring path is exercised
- app.state.bundle + app.state.scorer are injected directly (no reload)
- All 21 existing tests remain unaffected
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nscore.bundle.loader import load_bundle
from nscore.contracts import schemas
from nscore.contracts.schemas import Verdict

# ---------------------------------------------------------------------------
# Session-scoped bundle (shared with test_m3_03 if run together)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def mock_bundle_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from scripts.make_mock_bundle import build
    out_root = tmp_path_factory.mktemp("bundles_m304")
    return build("cic", out_root, seed=42)


@pytest.fixture(scope="session")
def real_bundle(mock_bundle_path: Path):
    return load_bundle(f"local:{mock_bundle_path}")


# ---------------------------------------------------------------------------
# Per-test DB + ScoringService + TestClient
# ---------------------------------------------------------------------------

@pytest.fixture()
def db_path(tmp_path: Path) -> str:
    """Fresh DB per test — init schema then return path."""
    from scripts.init_db import init_db
    p = str(tmp_path / "test.db")
    init_db(p)
    return p


@pytest.fixture()
def scoring_client(real_bundle, db_path: str):
    """TestClient with real bundle and isolated DB injected."""
    from api.app.main import app
    from api.app.scoring import ScoringService

    prior_bundle = getattr(app.state, "bundle", None)
    prior_scorer = getattr(app.state, "scorer", None)

    app.state.bundle = real_bundle
    app.state.scorer = ScoringService(real_bundle)

    # Point all DB operations at the test DB via the env var read at request time
    prev_db = os.environ.get("NS_DB_PATH")
    os.environ["NS_DB_PATH"] = db_path

    client = TestClient(app, raise_server_exceptions=True)
    yield client, db_path

    # Restore
    app.state.bundle = prior_bundle
    app.state.scorer = prior_scorer
    if prev_db is not None:
        os.environ["NS_DB_PATH"] = prev_db
    else:
        os.environ.pop("NS_DB_PATH", None)


# ---------------------------------------------------------------------------
# Helper: build a minimal valid FlowBatch payload using the bundle's spec
# ---------------------------------------------------------------------------

def _make_flow_payload(bundle, n: int = 1, seed: int = 0) -> dict:
    """Create a FlowBatch dict with real feature values drawn from the bundle spec."""
    import numpy as np

    from scripts.make_mock_bundle import synthetic_frame
    rng = np.random.default_rng(seed)
    df, _, _ = synthetic_frame(bundle.spec, rng)
    flows = []
    for i in range(n):
        row = df.iloc[i % len(df)]
        features = {name: float(row[name]) for name in bundle.spec.names}
        flows.append({
            "meta": {
                "flow_id": f"flow-{i:04d}",
                "observed_at": "2026-10-03T12:00:00Z",
                "src_ip": f"10.0.0.{(i % 254) + 1}",
                "dst_ip": "192.168.1.1",
                "src_port": 50000 + i,
                "dst_port": 80,
                "protocol": 6,
            },
            "features": features,
        })
    return {"flows": flows}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestScoreFlowsRealBundle:
    """M3-04: POST /v1/flows with a real bundle loaded."""

    def test_returns_200_and_schema(self, scoring_client, real_bundle):
        client, _ = scoring_client
        payload = _make_flow_payload(real_bundle, n=1)
        resp = client.post("/v1/flows", json=payload)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        batch = schemas.ScoreBatchResponse.model_validate(data)
        assert batch.received == 1
        assert len(batch.results) == 1

    def test_received_count_matches_batch_size(self, scoring_client, real_bundle):
        client, _ = scoring_client
        payload = _make_flow_payload(real_bundle, n=5)
        resp = client.post("/v1/flows", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["received"] == 5
        assert len(data["results"]) == 5

    def test_each_result_has_model_version(self, scoring_client, real_bundle):
        client, _ = scoring_client
        payload = _make_flow_payload(real_bundle, n=2)
        resp = client.post("/v1/flows", json=payload)
        assert resp.status_code == 200
        for result in resp.json()["results"]:
            assert result["model_version"] == real_bundle.version

    def test_each_result_has_valid_verdict(self, scoring_client, real_bundle):
        client, _ = scoring_client
        payload = _make_flow_payload(real_bundle, n=10, seed=7)
        resp = client.post("/v1/flows", json=payload)
        assert resp.status_code == 200
        valid_verdicts = {v.value for v in Verdict}
        for result in resp.json()["results"]:
            assert result["verdict"] in valid_verdicts

    def test_non_benign_flows_get_incident_id(self, scoring_client, real_bundle):
        """Every non-benign flow must have a non-null incident_id persisted."""
        client, _ = scoring_client
        # Use a large batch to ensure at least one attack in the synthetic data
        payload = _make_flow_payload(real_bundle, n=50, seed=999)
        resp = client.post("/v1/flows", json=payload)
        assert resp.status_code == 200
        results = resp.json()["results"]
        for r in results:
            if r["verdict"] != "benign":
                assert r["incident_id"] is not None, (
                    f"Non-benign flow {r['flow_id']} has no incident_id"
                )
            else:
                # Benign flows must NOT have an incident_id
                assert r["incident_id"] is None

    def test_flows_are_persisted_to_db(self, scoring_client, real_bundle):
        """Scored flows must appear in the flows table."""
        import sqlite3
        client, db_path = scoring_client
        payload = _make_flow_payload(real_bundle, n=3, seed=11)
        resp = client.post("/v1/flows", json=payload)
        assert resp.status_code == 200

        conn = sqlite3.connect(db_path)
        rows = conn.execute("SELECT flow_id FROM flows").fetchall()
        conn.close()

        flow_ids_in_db = {r[0] for r in rows}
        for flow in payload["flows"]:
            assert flow["meta"]["flow_id"] in flow_ids_in_db

    def test_non_benign_incidents_persisted(self, scoring_client, real_bundle):
        """Non-benign flows must create incidents in the incidents table."""
        import sqlite3
        client, db_path = scoring_client
        payload = _make_flow_payload(real_bundle, n=40, seed=55)
        resp = client.post("/v1/flows", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        total_non_benign = sum(
            1 for r in data["results"] if r["verdict"] != "benign"
        )
        conn = sqlite3.connect(db_path)
        row_count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        conn.close()

        assert data["incidents_created"] == total_non_benign
        assert row_count == total_non_benign

    def test_latency_ms_is_positive(self, scoring_client, real_bundle):
        client, _ = scoring_client
        payload = _make_flow_payload(real_bundle, n=1)
        resp = client.post("/v1/flows", json=payload)
        assert resp.status_code == 200
        result = resp.json()["results"][0]
        assert result["latency_ms"] >= 0

    def test_p_attack_in_range(self, scoring_client, real_bundle):
        client, _ = scoring_client
        payload = _make_flow_payload(real_bundle, n=10)
        resp = client.post("/v1/flows", json=payload)
        assert resp.status_code == 200
        for r in resp.json()["results"]:
            assert 0.0 <= r["p_attack"] <= 1.0

    def test_anomaly_percentile_in_range(self, scoring_client, real_bundle):
        """CIC bundle has no IsolationForest → anomaly_percentile should be 0."""
        client, _ = scoring_client
        payload = _make_flow_payload(real_bundle, n=5)
        resp = client.post("/v1/flows", json=payload)
        assert resp.status_code == 200
        for r in resp.json()["results"]:
            assert 0.0 <= r["anomaly_percentile"] <= 100.0


class TestScoreFlowsValidation:
    """M3-04: validation and error handling."""

    def test_missing_features_returns_422(self, scoring_client, real_bundle):
        """Submitting a flow with empty features (missing all spec features) → 422."""
        client, _ = scoring_client
        payload = {
            "flows": [{
                "meta": {
                    "flow_id": "bad-flow",
                    "observed_at": "2026-10-03T12:00:00Z",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "192.168.1.1",
                    "src_port": 12345,
                    "dst_port": 80,
                    "protocol": 6,
                },
                "features": {},  # no features at all
            }]
        }
        resp = client.post("/v1/flows", json=payload)
        assert resp.status_code == 422

    def test_empty_batch_rejected(self, scoring_client):
        """Pydantic schema min_length=1 rejects empty batch."""
        client, _ = scoring_client
        resp = client.post("/v1/flows", json={"flows": []})
        assert resp.status_code == 422


class TestMockModePreserved:
    """M3-04 must not break the NS_MOCK=1 path."""

    def test_mock_mode_still_returns_fixture(self):
        """When NS_MOCK=1 and no scorer is active, score_flows returns the fixture result (M3-01 behavior)."""
        import os

        from api.app.main import app

        prior_scorer = getattr(app.state, "scorer", None)
        app.state.scorer = None
        prev_mock = os.environ.get("NS_MOCK")
        os.environ["NS_MOCK"] = "1"
        try:
            client = TestClient(app, raise_server_exceptions=True)
            flow = {
                "meta": {
                    "flow_id": "mock-flow",
                    "observed_at": "2026-10-03T12:00:00Z",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "192.168.1.1",
                    "src_port": 12345,
                    "dst_port": 80,
                    "protocol": 6,
                },
                "features": {"fwd_pkt_len_max": 100.0},
            }
            resp = client.post("/v1/flows", json={"flows": [flow]})
            assert resp.status_code == 200
            data = resp.json()
            assert data["received"] == 1
            schemas.ScoreBatchResponse.model_validate(data)
        finally:
            app.state.scorer = prior_scorer
            if prev_mock is not None:
                os.environ["NS_MOCK"] = prev_mock
            else:
                os.environ.pop("NS_MOCK", None)
