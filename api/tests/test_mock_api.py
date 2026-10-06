import pytest
from fastapi.testclient import TestClient

from api.app.main import app
from api.tests.helpers import AUTH_HEADERS
from nscore.contracts import schemas

client = TestClient(app)


@pytest.fixture(autouse=True)
def _mock_mode(monkeypatch):
    monkeypatch.setenv("NS_MOCK", "1")

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["model_loaded"] is True

def test_docs():
    response = client.get("/docs")
    assert response.status_code == 200
    assert "Swagger UI" in response.text

def test_get_model_info():
    response = client.get("/v1/model")
    assert response.status_code == 200
    schemas.ModelInfo.model_validate(response.json())

def test_get_model_evaluation():
    response = client.get("/v1/model/evaluation")
    assert response.status_code == 200
    schemas.EvaluationReport.model_validate(response.json())

def test_score_flows():
    flow = {
        "meta": {
            "flow_id": "f1",
            "observed_at": "2026-10-03T00:00:00Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": 6
        },
        "features": {
            "fwd_pkt_len_max": 100
        }
    }
    response = client.post("/v1/flows", json={"flows": [flow]}, headers=AUTH_HEADERS)
    assert response.status_code == 200
    schemas.ScoreBatchResponse.model_validate(response.json())

def test_get_incidents():
    response = client.get("/v1/incidents")
    assert response.status_code == 200
    schemas.IncidentPage.model_validate(response.json())

def test_get_incident():
    response = client.get("/v1/incidents/inc-123")
    assert response.status_code == 200
    data = response.json()
    assert data["incident_id"] == "inc-123"
    schemas.IncidentDetail.model_validate(data)

def test_add_incident_action():
    response = client.post(
        "/v1/incidents/inc-123/actions", 
        json={"action": "acknowledge"}, 
        headers={"X-Analyst": "analyst-1 + Analyst"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["incident_id"] == "inc-123"
    assert data["action"] == "acknowledge"
    assert data["analyst"] == "analyst-1 + Analyst"
    schemas.AnalystActionRecord.model_validate(data)

def test_get_incident_brief():
    response = client.get("/v1/incidents/inc-123/brief")
    assert response.status_code == 200
    schemas.Brief.model_validate(response.json())

def test_get_drift():
    response = client.get("/v1/drift")
    assert response.status_code == 200
    schemas.DriftReport.model_validate(response.json())

def test_get_metrics():
    response = client.get("/v1/metrics")
    assert response.status_code == 200
    schemas.LiveMetrics.model_validate(response.json())

def test_reload_model():
    response = client.post("/v1/admin/reload-model", json={"model_ref": "azureml:netsentinel-bundle:2"},
                           headers=AUTH_HEADERS)
    assert response.status_code == 200
    schemas.ModelInfo.model_validate(response.json())
