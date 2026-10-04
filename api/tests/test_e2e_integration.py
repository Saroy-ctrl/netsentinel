import pytest
from fastapi.testclient import TestClient

from api.app.main import app
from api.tests.helpers import one_flow_batch

client = TestClient(app)

@pytest.fixture
def test_client(monkeypatch):
    monkeypatch.setenv("NS_MOCK", "1")
    monkeypatch.setenv("NS_API_KEY", "test_api_key")
    monkeypatch.setenv("NS_ADMIN_KEY", "admin_secret")
    # Using mock mode to test the pipeline flow
    return client

def test_full_pipeline_lifecycle(test_client):
    # 1. Ingest
    batch = one_flow_batch("flow-999")
    
    response = test_client.post("/v1/flows", json=batch, headers={"x-api-key": "test_api_key"})
    assert response.status_code == 200
    data = response.json()
    assert data["incidents_created"] >= 0

    # 2. Retrieve
    response = test_client.get("/v1/incidents")
    assert response.status_code == 200
    incidents = response.json().get("items", [])
    assert len(incidents) > 0
    incident_id = incidents[0]["incident_id"]

    # 3. Enrich
    response = test_client.get(f"/v1/incidents/{incident_id}/brief")
    assert response.status_code == 200
    brief_data = response.json()
    assert "text" in brief_data

    # 4. Triage
    response = test_client.post(
        f"/v1/incidents/{incident_id}/actions",
        json={"action": "acknowledge", "note": "Checked out this alert"},
        headers={"x-analyst": "Alice + Tier 2"}
    )
    assert response.status_code == 200
    action_data = response.json()
    assert action_data["action"] == "acknowledge"

    # 5. Verify Metrics
    response = test_client.get("/v1/metrics")
    assert response.status_code == 200
    metrics = response.json()
    assert metrics["flows_scored_total"] >= 0

def test_adverse_paths(test_client):
    # Malformed flow payloads resulting in formatted 422 responses
    response = test_client.post("/v1/flows", json={"flows": [{}]}, headers={"x-api-key": "test_api_key"})
    assert response.status_code == 422
    
    # Missing API Key
    response = test_client.post("/v1/flows", json=one_flow_batch())
    assert response.status_code == 403

    # Invalid Analyst Header
    response = test_client.post(
        "/v1/incidents/inc-1/actions",
        json={"action": "acknowledge", "note": "test"},
        headers={"x-analyst": "BadFormatHeader"}
    )
    assert response.status_code == 422
