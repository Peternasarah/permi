# db/database.py
# Handles all database creation and connection logic.
#
# Database location: ~/.permi/permi.db
# This works correctly whether Permi was installed via pip or run from source.
# The ~/.permi directory is created automatically on first use.
#
# FIX v0.2.17: DB_PATH is now computed lazily via get_db_path().
# Previously it was computed at module-level which caused Windows machines
# with Defender/antivirus to freeze on import — before the banner even appeared.

import sqlite3
from pathlib import Path


def get_permi_dir() -> Path:
    """
    Return the ~/.permi directory, creating it if it doesn't exist.
    This is the single source of truth for all Permi user data.

    Windows : C:\\Users\\<username>\\.permi
    macOS   : /Users/<username>/.permi
    Linux   : /home/<username>/.permi
    """
    permi_dir = Path.home() / ".permi"
    permi_dir.mkdir(parents=True, exist_ok=True)
    return permi_dir


from typing import Optional

# ── Lazy path resolution ──────────────────────────────────────────────────────
# Never compute these at module load time — that triggers filesystem access
# on import, which causes Windows Defender to freeze the process before
# any CLI output appears.
_DB_PATH:     Optional[Path] = None
_CONFIG_PATH: Optional[Path] = None


def get_db_path() -> Path:
    """Return the database path, computing it on first call only."""
    global _DB_PATH
    if _DB_PATH is None:
        _DB_PATH = get_permi_dir() / "permi.db"
    return _DB_PATH


# Keep DB_PATH as a module-level property for backward compatibility
# with any code that imports it directly. It now resolves lazily.
class _LazyPath:
    """Proxy that resolves the path only when first accessed."""
    def __truediv__(self, other):  return get_db_path() / other
    def __str__(self):             return str(get_db_path())
    def __repr__(self):            return repr(get_db_path())
    def __fspath__(self):          return str(get_db_path())
    def __eq__(self, other):       return get_db_path() == other
    def exists(self):              return get_db_path().exists()
    @property
    def name(self):                return get_db_path().name
    @property
    def parent(self):              return get_db_path().parent


DB_PATH = _LazyPath()


def get_connection() -> sqlite3.Connection:
    """
    Open and return a connection to the local SQLite database.
    Sets row_factory so rows behave like dictionaries.
    """
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """
    Create all tables if they don't already exist.
    Safe to call every time the app starts.
    """
    conn = get_connection()

    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL,
                path        TEXT    NOT NULL,
                created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                last_scan   TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id     INTEGER NOT NULL REFERENCES projects(id),
                started_at     TEXT    NOT NULL DEFAULT (datetime('now')),
                finished_at    TEXT,
                total_files    INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                status         TEXT    DEFAULT 'running'
            )
        """)

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
