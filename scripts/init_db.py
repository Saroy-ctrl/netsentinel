import os
import sqlite3
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from api.app.db import get_connection

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
  flow_id TEXT PRIMARY KEY, observed_at TEXT, received_at TEXT,
  src_ip TEXT, dst_ip TEXT, src_port INT, dst_port INT, protocol INT,
  features_json TEXT, verdict TEXT, p_attack REAL, anomaly_pct REAL,
  attack_family TEXT, severity REAL, incident_id TEXT REFERENCES incidents(incident_id),
  ground_truth TEXT, model_version TEXT, latency_ms REAL
);
CREATE TABLE IF NOT EXISTS incidents (
  incident_id TEXT PRIMARY KEY, status TEXT DEFAULT 'new', verdict TEXT, attack_family TEXT,
  mitre_id TEXT, mitre_name TEXT, risk_score INT, risk_level TEXT, severity REAL, max_confidence REAL,
  flow_count INT, src_ip TEXT, dst_ip TEXT, dst_port INT, first_seen TEXT, last_seen TEXT,
  top_features_json TEXT, brief_json TEXT, model_version TEXT,
  acknowledged_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS analyst_actions (
  action_id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT REFERENCES incidents(incident_id),
  analyst TEXT NOT NULL, action TEXT NOT NULL, note TEXT, at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS drift_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT, computed_at TEXT, model_version TEXT, window_size INT,
  status TEXT, max_psi REAL, report_json TEXT
);
CREATE INDEX IF NOT EXISTS ix_inc_open ON incidents(status, risk_score DESC);
CREATE INDEX IF NOT EXISTS ix_inc_key  ON incidents(src_ip, dst_ip, attack_family, last_seen);
"""

def init_db(db_path: str = None):
    from api.app.db import DB_PATH
    path = db_path or DB_PATH
    conn = get_connection(path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
        print(f"Database initialized at {path}")
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
