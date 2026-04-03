# db/database.py
# Handles all database creation and connection logic.
# The database file (permi.db) is created automatically in the
# project root the first time this module is imported.

import sqlite3
from pathlib import Path

# The database lives in the project root folder
DB_PATH = Path(__file__).parent.parent / "permi.db"


def get_connection() -> sqlite3.Connection:
    """
    Open and return a connection to the local SQLite database.
    Sets row_factory so rows behave like dictionaries — you can
    access columns by name (row['severity']) instead of index (row[2]).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")  # enforce relationships
    return conn


def init_db() -> None:
    """
    Create all tables if they don't already exist.
    Safe to call every time the app starts — won't overwrite existing data.
    """
    conn = get_connection()

    with conn:

        # ── projects ──────────────────────────────────────────────────────────
        # One row per codebase you want to scan repeatedly.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL,
                path        TEXT    NOT NULL,
                created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                last_scan   TEXT
            )
        """)

        # ── scan_results ──────────────────────────────────────────────────────
        # One row per scan run. Links back to the project that was scanned.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id    INTEGER NOT NULL REFERENCES projects(id),
                started_at    TEXT    NOT NULL DEFAULT (datetime('now')),
                finished_at   TEXT,
                total_files   INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                status        TEXT    DEFAULT 'running'
            )
        """)

        # ── findings ──────────────────────────────────────────────────────────
        # One row per vulnerability found in a scan.
        # ai_verdict and ai_explanation are NULL until Phase 1 fills them in.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         INTEGER NOT NULL REFERENCES scan_results(id),
                rule_id         TEXT    NOT NULL,
                rule_name       TEXT    NOT NULL,
                severity        TEXT    NOT NULL,
                description     TEXT,
                file            TEXT    NOT NULL,
                line_number     INTEGER NOT NULL,
                line_content    TEXT,
                ai_verdict      TEXT,
                ai_explanation  TEXT,
                fix_suggestion  TEXT,
                created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
            )
        """)

        # ── feedback ──────────────────────────────────────────────────────────
        # Stores manual corrections from the user.
        # 'confirmed' = real vulnerability, 'false_positive' = not a real issue.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id   INTEGER NOT NULL REFERENCES findings(id),
                verdict      TEXT    NOT NULL CHECK(verdict IN ('confirmed', 'false_positive')),
                note         TEXT,
                created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
            )
        """)

    conn.close()
    print(f"Database ready: {DB_PATH}")
