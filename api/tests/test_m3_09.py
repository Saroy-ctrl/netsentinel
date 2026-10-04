import pytest
from fastapi.testclient import TestClient

from api.app.main import app

client = TestClient(app)

@pytest.fixture
def test_client(monkeypatch):
    monkeypatch.setenv("NS_MOCK", "1")
    monkeypatch.setenv("NS_ADMIN_KEY", "test_admin")
    return client

def test_get_incident_brief_mock(test_client):
    response = test_client.get("/v1/incidents/inc-123/brief")
    assert response.status_code == 200
    data = response.json()
    assert data["incident_id"] == "inc-123"
    assert data["source"] == "template"

def test_admin_reload_auth(test_client):
    # No header
    response = test_client.post("/v1/admin/reload-model", json={"model_ref": "local:artifacts/bundles/mock-cic"})
    assert response.status_code == 403

    # Invalid header
    response = test_client.post(
        "/v1/admin/reload-model",
        json={"model_ref": "local:artifacts/bundles/mock-cic"},
        headers={"x-admin-key": "invalid"}
    )
    assert response.status_code == 403

def test_admin_reload_success(test_client):
    response = test_client.post(
        "/v1/admin/reload-model",
        json={"model_ref": "local:artifacts/bundles/mock-cic"},
        headers={"x-admin-key": "test_admin"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "model_version" in data

@pytest.mark.asyncio
async def test_brief_service_timeout_and_constraints(monkeypatch):
    from api.app.services.brief import generate_and_cache_brief
    
    class DummyRepo:
        def update_incident_brief(self, i_id, b_json):
            pass
            
    # Test timeout
    incident_data = {"risk_level": "CRITICAL", "_test_timeout": True}
    brief = await generate_and_cache_brief("inc-1", incident_data, DummyRepo(), timeout=0.01)
    assert brief.source == "template"
    assert "Timeout" in brief.text or "Fallback" in brief.text
    
    # Test wording constraints
    incident_data = {"attack_family": "novel_anomaly", "verdict": "Malicious", "_test_timeout": False}
    brief = await generate_and_cache_brief("inc-2", incident_data, DummyRepo(), timeout=2.0)
    assert brief.source == "llm"
    assert "novel_anomaly" in brief.text
    assert "Malicious" in brief.text
