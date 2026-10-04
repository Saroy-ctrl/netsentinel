import sqlite3
from typing import Any


class Repository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def get_incident(self, incident_id: str) -> sqlite3.Row | None:
        cur = self.conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
        return cur.fetchone()
        
    def create_incident(self, data: dict[str, Any]) -> str:
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        query = f"INSERT INTO incidents ({columns}) VALUES ({placeholders})"
        self.conn.execute(query, tuple(data.values()))
        return data["incident_id"]

    def update_incident(self, incident_id: str, data: dict[str, Any]):
        set_clause = ", ".join([f"{k} = ?" for k in data.keys()])
        query = f"UPDATE incidents SET {set_clause} WHERE incident_id = ?"
        self.conn.execute(query, tuple(data.values()) + (incident_id,))

    def update_incident_brief(self, incident_id: str, brief_json: str):
        query = "UPDATE incidents SET brief_json = ? WHERE incident_id = ?"
        self.conn.execute(query, (brief_json, incident_id))
        self.conn.commit()

    def list_incidents(self, status: str | None = None, limit: int = 50, offset: int = 0) -> list[sqlite3.Row]:
        query = "SELECT * FROM incidents"
        params = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY risk_score DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cur = self.conn.execute(query, tuple(params))
        return cur.fetchall()

    def create_flow(self, data: dict[str, Any]):
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        query = f"INSERT INTO flows ({columns}) VALUES ({placeholders})"
        self.conn.execute(query, tuple(data.values()))

    def add_analyst_action(self, data: dict[str, Any]) -> int:
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        query = f"INSERT INTO analyst_actions ({columns}) VALUES ({placeholders})"
        cur = self.conn.execute(query, tuple(data.values()))
        return cur.lastrowid
        
    def create_drift_snapshot(self, data: dict[str, Any]) -> int:
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        query = f"INSERT INTO drift_snapshots ({columns}) VALUES ({placeholders})"
        cur = self.conn.execute(query, tuple(data.values()))
        return cur.lastrowid
