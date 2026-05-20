# scanner/intelligence.py
# Permi Scan Intelligence Layer
#
# PURPOSE
# -------
# Every scan Permi runs teaches something about how African fintech code fails.
# This module captures that learning anonymously and locally — building the
# accumulated intelligence that becomes Permi's moat over time.
#
# From the Permi strategic roadmap:
#   "After 500 scans of Nigerian fintech code, Permi will know things about
#    how Nigerian developers make security mistakes that no foreign tool will
#    ever know. That knowledge, encoded into rules, benchmarks, and remediation
#    templates, is the moat."
#
# DESIGN PRINCIPLES — TRUST FIRST
# --------------------------------
# 1. Everything stored locally in ~/.permi/intelligence.db — nothing leaves
#    the user's machine without explicit opt-in to the community feed.
# 2. No file paths stored — only rule IDs, severities, frameworks, patterns.
# 3. No code content stored — only aggregated counts and signatures.
# 4. Opt-in community contribution is a separate, clearly explained step.
# 5. The user can inspect, export, or delete their intelligence data at any time.
# 6. This module never crashes a scan — all errors are silently swallowed.
#
# WHAT IS COLLECTED (locally, always)
# ------------------------------------
# - Which rules fired and how many times (aggregate counts)
# - Which rules the AI filter marked as FP most often (quality signal)
# - Which fix templates were shown (proxy for what developers encounter)
# - Which frameworks appear in scanned codebases (Python, JS, PHP, etc.)
# - Which Nigerian payment APIs appear in code (Paystack, Flutterwave, etc.)
# - Scan mode (path vs url) — helps prioritise which scanner to improve
# - Finding severity distribution — tells us where real risk concentrates
#
# WHAT IS NEVER COLLECTED
# -----------------------
# - File paths or directory names
# - Code content of any kind
# - Project names
# - URLs scanned (even in url mode)
# - Personal data of any kind
# - Usernames, emails, API keys

from __future__ import annotations

import json
import hashlib
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any


# ── Constants ─────────────────────────────────────────────────────────────────

# Nigerian payment APIs and frameworks we track for intelligence
KNOWN_PAYMENT_APIS = {
    "paystack", "flutterwave", "monnify", "opay", "moniepoint",
    "interswitch", "remita", "gtpay", "upay", "providus",
}

KNOWN_FRAMEWORKS = {
    "flask", "django", "fastapi", "express", "koa", "nestjs",
    "laravel", "codeigniter", "symfony", "spring", "rails",
    "nextjs", "nuxt", "react", "vue", "angular",
}


# ── Database ──────────────────────────────────────────────────────────────────

def _get_intel_db_path() -> Path:
    """Get the intelligence database path lazily."""
    from db.database import get_permi_dir
    return get_permi_dir() / "intelligence.db"


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(_get_intel_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def _init_intelligence_db() -> None:
    """Create the intelligence tables if they do not exist."""
    try:
        conn = _get_connection()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rule_stats (
                    rule_id          TEXT    PRIMARY KEY,
                    fires_total      INTEGER DEFAULT 0,
                    fires_real       INTEGER DEFAULT 0,
                    fires_fp         INTEGER DEFAULT 0,
                    fires_review     INTEGER DEFAULT 0,
                    fires_unavail    INTEGER DEFAULT 0,
                    last_fired       TEXT,
                    updated_at       TEXT    DEFAULT (datetime('now'))
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_aggregates (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_date        TEXT    NOT NULL,
                    scan_mode        TEXT    NOT NULL,
                    raw_count        INTEGER DEFAULT 0,
                    real_count       INTEGER DEFAULT 0,
                    fp_count         INTEGER DEFAULT 0,
                    high_count       INTEGER DEFAULT 0,
                    medium_count     INTEGER DEFAULT 0,
                    low_count        INTEGER DEFAULT 0,
                    frameworks_seen  TEXT    DEFAULT '[]',
                    payment_apis_seen TEXT   DEFAULT '[]',
                    duration_seconds INTEGER DEFAULT 0
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS framework_counts (
                    framework        TEXT    PRIMARY KEY,
                    seen_count       INTEGER DEFAULT 0,
                    last_seen        TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS payment_api_counts (
                    api_name         TEXT    PRIMARY KEY,
                    seen_count       INTEGER DEFAULT 0,
                    times_exposed    INTEGER DEFAULT 0,
                    last_seen        TEXT
                )
            """)

        conn.close()
    except Exception:
        pass  # Intelligence collection must never crash a scan


# ── Framework and API detection ───────────────────────────────────────────────

def _detect_frameworks(findings: List[Dict]) -> List[str]:
    """
    Detect which frameworks are likely present based on finding context.
    Uses file extensions and finding descriptions — never stores the actual code.
    """
    detected = set()
    for f in findings:
        file_path = f.get("file", "").lower()
        desc      = f.get("description", "").lower()
        content   = f.get("line_content", "").lower()

        if ".py" in file_path:
            if "flask" in content or "flask" in desc:
                detected.add("flask")
            elif "django" in content or "django" in desc:
                detected.add("django")
            elif "fastapi" in content or "fastapi" in desc:
                detected.add("fastapi")
            else:
                detected.add("python")

        if ".js" in file_path or ".ts" in file_path:
            if "express" in content:
                detected.add("express")
            elif "next" in content:
                detected.add("nextjs")
            elif "react" in content:
                detected.add("react")
            elif "vue" in content:
                detected.add("vue")
            else:
                detected.add("javascript")

        if ".php" in file_path:
            if "laravel" in content:
                detected.add("laravel")
            elif "codeigniter" in content:
                detected.add("codeigniter")
            else:
                detected.add("php")

        if ".java" in file_path:
            detected.add("java")
        if ".rb" in file_path:
            detected.add("rails")

    return list(detected)


def _detect_payment_apis(findings: List[Dict]) -> List[str]:
    """
    Detect which Nigerian payment APIs are referenced in the scanned code.
    Only tracks presence, never stores keys or values.
    """
    detected = set()
    for f in findings:
        content = (f.get("line_content", "") + f.get("description", "")).lower()
        for api in KNOWN_PAYMENT_APIS:
            if api in content:
                detected.add(api)
    return list(detected)


# ── Core recording function ───────────────────────────────────────────────────

def record_scan(
    findings:         List[Dict],
    raw_count:        int,
    scan_mode:        str,
    duration_seconds: int = 0,
) -> None:
    """
    Record anonymised intelligence from a completed scan.

    Called automatically after every scan. Stores only aggregate counts and
    patterns — never file paths, code content, project names, or URLs.

    Parameters
    ----------
    findings : confirmed real findings (after AI filter)
    raw_count : number of raw findings before filtering
    scan_mode : "path" or "url"
    duration_seconds : how long the scan took
    """
    try:
        _init_intelligence_db()
        conn = _get_connection()
        now  = datetime.utcnow().isoformat()

        # Compute aggregate counts
        real_count   = len(findings)
        fp_count     = max(0, raw_count - real_count)
        high_count   = sum(1 for f in findings if f.get("severity") == "high")
        medium_count = sum(1 for f in findings if f.get("severity") == "medium")
        low_count    = sum(1 for f in findings if f.get("severity") == "low")

        # Detect frameworks and payment APIs
        frameworks   = _detect_frameworks(findings)
        payment_apis = _detect_payment_apis(findings)

        with conn:
            # Record scan aggregate
            conn.execute("""
                INSERT INTO scan_aggregates
                    (scan_date, scan_mode, raw_count, real_count, fp_count,
                     high_count, medium_count, low_count,
                     frameworks_seen, payment_apis_seen, duration_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                now[:10], scan_mode, raw_count, real_count, fp_count,
                high_count, medium_count, low_count,
                json.dumps(frameworks), json.dumps(payment_apis),
                duration_seconds,
            ))

            # Update per-rule stats
            for f in findings:
                rule_id = f.get("rule_id", "UNKNOWN")
                verdict = f.get("ai_verdict", "AI_UNAVAILABLE")
                conn.execute("""
                    INSERT INTO rule_stats (rule_id, fires_total, last_fired)
                    VALUES (?, 1, ?)
                    ON CONFLICT(rule_id) DO UPDATE SET
                        fires_total = fires_total + 1,
                        last_fired  = excluded.last_fired,
                        updated_at  = excluded.last_fired
                """, (rule_id, now))

                col_map = {
                    "REAL":           "fires_real",
                    "FP":             "fires_fp",
                    "REVIEW":         "fires_review",
                    "AI_UNAVAILABLE": "fires_unavail",
                }
                col = col_map.get(verdict)
                if col:
                    conn.execute(
                        f"UPDATE rule_stats SET {col} = {col} + 1 WHERE rule_id = ?",
                        (rule_id,)
                    )

            # Update framework counts
            for fw in frameworks:
                conn.execute("""
                    INSERT INTO framework_counts (framework, seen_count, last_seen)
                    VALUES (?, 1, ?)
                    ON CONFLICT(framework) DO UPDATE SET
                        seen_count = seen_count + 1,
                        last_seen  = excluded.last_seen
                """, (fw, now))

            # Update payment API counts
            for api in payment_apis:
                exposed = 1 if any(
                    f.get("rule_id", "").startswith("SEC")
                    and api in f.get("line_content", "").lower()
                    for f in findings
                ) else 0
                conn.execute("""
                    INSERT INTO payment_api_counts (api_name, seen_count, times_exposed, last_seen)
                    VALUES (?, 1, ?, ?)
                    ON CONFLICT(api_name) DO UPDATE SET
                        seen_count    = seen_count + 1,
                        times_exposed = times_exposed + excluded.times_exposed,
                        last_seen     = excluded.last_seen
                """, (api, exposed, now))

        conn.close()

    except Exception:
        pass  # Intelligence collection must NEVER crash a scan


# ── Query functions (for permi stats command) ─────────────────────────────────

def get_local_stats() -> Dict[str, Any]:
    """
    Return aggregated local scan intelligence.
    Used by `permi stats` command to show the user their own accumulated data.
    """
    try:
        _init_intelligence_db()
        conn  = _get_connection()
        stats = {}

        # Total scans
        row = conn.execute("SELECT COUNT(*) as n, SUM(raw_count) as raw, SUM(real_count) as real, SUM(fp_count) as fp FROM scan_aggregates").fetchone()
        stats["total_scans"]    = row["n"] or 0
        stats["total_raw"]      = row["raw"] or 0
        stats["total_confirmed"] = row["real"] or 0
        stats["total_fp"]       = row["fp"] or 0
        stats["overall_noise_reduction"] = (
            round((stats["total_fp"] / stats["total_raw"]) * 100, 1)
            if stats["total_raw"] > 0 else 0
        )

        # Top rules
        rows = conn.execute(
            "SELECT rule_id, fires_total, fires_real, fires_fp FROM rule_stats ORDER BY fires_total DESC LIMIT 10"
        ).fetchall()
        stats["top_rules"] = [
            {
                "rule_id":    r["rule_id"],
                "total":      r["fires_total"],
                "real":       r["fires_real"],
                "fp":         r["fires_fp"],
                "precision":  round((r["fires_real"] / r["fires_total"]) * 100, 1) if r["fires_total"] > 0 else 0,
            }
            for r in rows
        ]

        # Top frameworks
        rows = conn.execute(
            "SELECT framework, seen_count FROM framework_counts ORDER BY seen_count DESC LIMIT 10"
        ).fetchall()
        stats["top_frameworks"] = [{"name": r["framework"], "count": r["seen_count"]} for r in rows]

        # Payment API exposure
        rows = conn.execute(
            "SELECT api_name, seen_count, times_exposed FROM payment_api_counts ORDER BY seen_count DESC"
        ).fetchall()
        stats["payment_apis"] = [
            {"name": r["api_name"], "scanned": r["seen_count"], "exposed": r["times_exposed"]}
            for r in rows
        ]

        conn.close()
        return stats

    except Exception:
        return {}


def get_rule_precision_report() -> List[Dict]:
    """
    Return rules ranked by precision (real / total fires).
    Rules with low precision are candidates for improvement.
    Used internally to identify which rules generate the most noise.
    """
    try:
        _init_intelligence_db()
        conn = _get_connection()
        rows = conn.execute("""
            SELECT rule_id, fires_total, fires_real, fires_fp,
                   ROUND(CAST(fires_real AS FLOAT) / fires_total * 100, 1) as precision
            FROM rule_stats
            WHERE fires_total >= 3
            ORDER BY precision ASC
        """).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []
