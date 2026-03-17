"""SQLite database setup for live packet capture (auth tables now in Supabase)."""
from __future__ import annotations

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "cybershield.db"


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    """Initialize only the local SQLite tables (live packet capture).
    User authentication tables are stored in Supabase.
    """
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS captured_packets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT    DEFAULT '',
            dst_ip      TEXT    DEFAULT '',
            src_port    INTEGER DEFAULT 0,
            dst_port    INTEGER DEFAULT 0,
            protocol    TEXT    DEFAULT '',
            length      INTEGER DEFAULT 0,
            prediction  TEXT    DEFAULT 'UNKNOWN',
            confidence  REAL    DEFAULT 0.0,
            severity    TEXT    DEFAULT 'LOW',
            info        TEXT    DEFAULT ''
        );
    """)
    conn.commit()
    conn.close()
