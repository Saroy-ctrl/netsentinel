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
    return client

def test_cors_headers(test_client):
    response = test_client.options(
        "/v1/model",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        }
    )
    assert response.status_code == 200
    assert "access-control-allow-origin" in response.headers
    assert response.headers["access-control-allow-origin"] in ("http://localhost:3000", "*")

def test_ingest_auth(test_client):
    # No header
    response = test_client.post("/v1/flows", json=one_flow_batch())
    assert response.status_code == 403

    # Invalid header
    response = test_client.post("/v1/flows", json=one_flow_batch(), headers={"x-api-key": "invalid"})
    assert response.status_code == 403

    # Valid header (Mock mode returns 200/empty result without caring about flow content usually)
    response = test_client.post("/v1/flows", json=one_flow_batch(), headers={"x-api-key": "test_api_key"})
    assert response.status_code == 200

def test_analyst_header_format(test_client):
    incident_id = "inc-123"
    
    # Missing header
    response = test_client.post(f"/v1/incidents/{incident_id}/actions", json={"action": "acknowledge", "note": "test"})
    assert response.status_code == 422
    
    # Invalid format (no plus)
    url, body = f"/v1/incidents/{incident_id}/actions", {"action": "acknowledge", "note": "test"}
    response = test_client.post(url, json=body, headers={"x-analyst": "John Doe Tier 1"})
    assert response.status_code == 422

    # Valid format
    response = test_client.post(url, json=body, headers={"x-analyst": "John Doe + Tier 1"})
    assert response.status_code == 200

def test_structured_log_and_request_id(test_client, caplog):
    import logging
    caplog.set_level(logging.INFO)
    
    response = test_client.get("/health")
    assert response.status_code == 200
    assert "x-request-id" in response.headers
    req_id = response.headers["x-request-id"]
    
    # Check log
    found = False
    for record in caplog.records:
        if req_id in record.message and "duration_ms" in record.message:
            found = True
            break
    assert found

def test_missing_features_422_formatting(test_client, monkeypatch):
    # To test this, we need to trigger MissingFeaturesError.
    # In mock mode /v1/flows does not use the scorer, so the exception handler is exercised directly.
    # Since we just want to verify the exception handler works:
    import asyncio

    from fastapi import Request

    from api.app.main import missing_features_handler
    from nscore.features.transform import MissingFeaturesError
    
    req = Request({"type": "http", "method": "POST", "url": "http://testserver/v1/flows"})
    exc = MissingFeaturesError(["feature1", "feature2"])
    
    response = asyncio.run(missing_features_handler(req, exc))
    import json
    data = json.loads(response.body)
    assert "detail" in data
    assert len(data["detail"]) == 2
    assert data["detail"][0]["loc"] == ["body", "flows", "feature1"]
    assert data["detail"][0]["type"] == "value_error.missing"
