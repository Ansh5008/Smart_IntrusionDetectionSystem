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
    """Initialize only the local SQLite tables (live packet capture and IPS data).
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
        
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address  TEXT    UNIQUE NOT NULL,
            reason      TEXT    NOT NULL,
            timestamp   TEXT    NOT NULL,
            is_active   INTEGER DEFAULT 1
        );
        
        CREATE TABLE IF NOT EXISTS ips_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT    NOT NULL,
            action      TEXT    NOT NULL,   -- e.g., 'MONITOR', 'THROTTLE', 'BLOCK'
            reason      TEXT    NOT NULL,
            risk_score  REAL    DEFAULT 0.0
        );
        
        CREATE TABLE IF NOT EXISTS threat_intel (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address  TEXT    UNIQUE NOT NULL,
            threat_type TEXT    NOT NULL,
            added_at    TEXT    NOT NULL
        );
        
        CREATE TABLE IF NOT EXISTS system_settings (
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL
        );
        
        -- Default settings
        INSERT OR IGNORE INTO system_settings (key, value) VALUES ('auto_mode', 'Manual');
    """)
    conn.commit()
    conn.close()


def get_setting(key: str, default: str = "") -> str:
    """Retrieve a persistent system setting."""
    conn = get_connection()
    try:
        row = conn.execute("SELECT value FROM system_settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def set_setting(key: str, value: str) -> None:
    """Update or insert a persistent system setting."""
    conn = get_connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)",
            (key, value)
        )
        conn.commit()
    finally:
        conn.close()
