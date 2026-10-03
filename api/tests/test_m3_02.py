import os
import sqlite3
import pytest
import tempfile
from api.app.db import get_connection
from api.app.repository import Repository
from scripts.init_db import init_db

@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    # Set env var for init_db
    os.environ["NS_DB_PATH"] = path
    yield path
    os.remove(path)

def test_schema_creation_and_safe_init(temp_db):
    # Initialize once
    init_db(temp_db)
    
    # Verify tables
    conn = get_connection(temp_db)
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {row[0] for row in cur.fetchall()}
    assert {"flows", "incidents", "analyst_actions", "drift_snapshots"}.issubset(tables)

    # Verify indexes
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
    indexes = {row[0] for row in cur.fetchall()}
    assert "ix_inc_open" in indexes
    assert "ix_inc_key" in indexes

    # Verify WAL mode
    cur = conn.execute("PRAGMA journal_mode")
    assert cur.fetchone()[0].lower() == "wal"
    conn.close()

    # Verify safe to run again (no exception)
    init_db(temp_db)

def test_repository_operations(temp_db):
    init_db(temp_db)
    conn = get_connection(temp_db)
    repo = Repository(conn)
    
    # Test incident creation
    incident_id = "inc-1"
    repo.create_incident({
        "incident_id": incident_id,
        "status": "new",
        "risk_score": 90,
        "risk_level": "HIGH",
        "attack_family": "Botnet"
    })
    
    # Test get incident
    incident = repo.get_incident(incident_id)
    assert incident is not None
    assert incident["risk_score"] == 90
    assert incident["status"] == "new"

    # Test update incident
    repo.update_incident(incident_id, {"status": "acknowledged", "flow_count": 2})
    incident = repo.get_incident(incident_id)
    assert incident["status"] == "acknowledged"
    assert incident["flow_count"] == 2

    # Test list incidents
    repo.create_incident({
        "incident_id": "inc-2",
        "status": "new",
        "risk_score": 40,
        "risk_level": "LOW",
        "attack_family": "WebAttack"
    })
    
    # List all
    all_incidents = repo.list_incidents()
    assert len(all_incidents) == 2
    # Check sorting
    assert all_incidents[0]["incident_id"] == "inc-1"  # 90 risk
    assert all_incidents[1]["incident_id"] == "inc-2"  # 40 risk

    # List by status
    new_incidents = repo.list_incidents(status="new")
    assert len(new_incidents) == 1
    assert new_incidents[0]["incident_id"] == "inc-2"

    # Test flow creation
    repo.create_flow({
        "flow_id": "f-1",
        "incident_id": incident_id,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2"
    })
    
    cur = conn.execute("SELECT * FROM flows WHERE flow_id = 'f-1'")
    assert cur.fetchone() is not None

    conn.close()
