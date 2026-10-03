import sqlite3
import os
from contextlib import contextmanager

DB_PATH = os.environ.get("NS_DB_PATH", "netsentinel.db")

def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    # Enable WAL mode
    conn.execute("PRAGMA journal_mode=WAL")
    # Enforce foreign keys
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn

@contextmanager
def db_session(db_path: str = DB_PATH):
    conn = get_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()
