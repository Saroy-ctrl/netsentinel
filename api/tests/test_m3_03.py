"""M3-03 tests: real bundle loading at startup.

Builds a temporary mock-cic bundle via make_mock_bundle.build(), directly
injects it into app.state.bundle, and verifies that /health, /v1/model, and
/v1/model/evaluation are served from the real bundle rather than the NS_MOCK=1
fixture.

Isolation guarantees
--------------------
- importlib.reload() is NOT used — avoids corrupting the shared IS_MOCK / _is_mock()
  state that test_mock_api.py depends on.
- The bundle is injected directly into app.state so it takes priority over the
  _is_mock() check (bundle check comes first in every endpoint).
- After the fixture scope ends, app.state.bundle is restored to its prior value.
- NS_MOCK is never permanently altered by this module.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nscore.bundle.loader import load_bundle
from nscore.contracts import schemas


# ---------------------------------------------------------------------------
# Session-scoped bundle fixture (build once, re-use across all tests here)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def mock_bundle_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build a real mock-cic bundle into a session-scoped temp directory."""
    from scripts.make_mock_bundle import build

    out_root = tmp_path_factory.mktemp("bundles")
    bundle_path = build("cic", out_root, seed=0)
    assert bundle_path.exists(), f"build() did not create bundle at {bundle_path}"
    return bundle_path


@pytest.fixture(scope="session")
def real_bundle(mock_bundle_path: Path):
    """Load the Bundle object for inspection and app.state injection."""
    return load_bundle(f"local:{mock_bundle_path}")


# ---------------------------------------------------------------------------
# TestClient with real bundle injected into app.state
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def bundle_client(real_bundle):
    """
    Return a TestClient backed by the real (mock-cic) bundle.

    Rather than reloading the module (which would corrupt IS_MOCK / _is_mock()
    for test_mock_api.py), we inject the bundle directly into app.state.
    The three M3-03 endpoints check _bundle() before _is_mock(), so the real
    bundle is always served regardless of NS_MOCK.
    """
    from api.app.main import app

    # Preserve whatever state was there (None if lifespan hasn't run)
    prior = getattr(app.state, "bundle", None)
    app.state.bundle = real_bundle

    # Use TestClient without context manager so lifespan doesn't overwrite
    # app.state.bundle with a load from MODEL_REF / the default path.
    client = TestClient(app, raise_server_exceptions=True)
    yield client

    # Restore previous state so other test modules are unaffected
    app.state.bundle = prior


# ---------------------------------------------------------------------------
# A. /health
# ---------------------------------------------------------------------------


def test_health_model_loaded(bundle_client: TestClient, real_bundle):
    response = bundle_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["model_loaded"] is True
    # model_version must come from the real bundle, not the fixture string
    assert data["model_version"] == real_bundle.version
    assert data["model_version"] != "nsb-0.0.0-fixture"


# ---------------------------------------------------------------------------
# B. /v1/model
# ---------------------------------------------------------------------------


def test_model_info_validates_as_schema(bundle_client: TestClient):
    response = bundle_client.get("/v1/model")
    assert response.status_code == 200
    info = schemas.ModelInfo.model_validate(response.json())
    assert info is not None


def test_model_info_feature_schema(bundle_client: TestClient):
    response = bundle_client.get("/v1/model")
    assert response.status_code == 200
    data = response.json()
    assert data["feature_schema"] == "cic"


def test_model_info_family_head(bundle_client: TestClient):
    response = bundle_client.get("/v1/model")
    assert response.status_code == 200
    data = response.json()
    # mock-cic is built with a RandomForestClassifier multiclass head
    assert data["family_head"] is True


def test_model_info_is_real_bundle_not_fixture(bundle_client: TestClient, real_bundle):
    response = bundle_client.get("/v1/model")
    assert response.status_code == 200
    data = response.json()
    # The model_version of the real bundle differs from the hardcoded fixture
    assert data["model_version"] == real_bundle.version
    assert data["model_version"] != "nsb-0.0.0-fixture"


# ---------------------------------------------------------------------------
# C. /v1/model/evaluation
# ---------------------------------------------------------------------------


def test_evaluation_report_validates_as_schema(bundle_client: TestClient):
    response = bundle_client.get("/v1/model/evaluation")
    assert response.status_code == 200
    report = schemas.EvaluationReport.model_validate(response.json())
    assert report is not None


def test_evaluation_report_mock_bundle_limitation(bundle_client: TestClient):
    response = bundle_client.get("/v1/model/evaluation")
    assert response.status_code == 200
    data = response.json()
    # make_mock_bundle.py sets: report["limitations"] = ["MOCK BUNDLE: synthetic data, meaningless metrics"]
    limitations = data.get("limitations", [])
    assert any("MOCK BUNDLE" in lim for lim in limitations), (
        f"Expected 'MOCK BUNDLE' in limitations, got: {limitations}"
    )
