# scanner/scan.py
# Full scan pipeline — engine + AI filter combined.

import json
from pathlib import Path

from scanner.engine import scan_directory as run_engine
from ai_filter.filter import run_filter
from db.database import init_db, get_connection
from db.queries import (
    create_project,
    start_scan,
    save_finding,
    finish_scan,
    update_last_scan,
    get_findings_for_scan,
)


def scan(path: str, project_name: str = None, offline: bool = False) -> list[dict]:
    """
    Full scan pipeline:
      1. Resolve path
      2. Create/find project in DB
      3. Start scan record
      4. Run rule engine over all files
      5. Save every raw finding to DB
      6. Run AI filter — updates ai_verdict in DB, drops false positives
      7. Finish scan record
      8. Return only REAL findings

    Args:
        path:         Local directory to scan.
        project_name: Optional display name. Defaults to folder name.
        offline:      If True, skip AI filter and return all raw findings.
    """
    # ── 1. Resolve path ───────────────────────────────────────────────────────
    target = Path(path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Path does not exist: {target}")
    if not target.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {target}")

    name = project_name or target.name

    # ── 2. Init DB and create/find project ────────────────────────────────────
    init_db()
    conn = get_connection()
    project_id = create_project(conn, name=name, path=str(target))

    # ── 3. Start scan record ──────────────────────────────────────────────────
    scan_id = start_scan(conn, project_id)

    print(f"\n[Permi] Scanning : {target}")
    print(f"[Permi] Project  : {name}  (id={project_id})")
    print(f"[Permi] Scan     : id={scan_id}\n")

    # ── 4. Run the engine ─────────────────────────────────────────────────────
    raw_findings = run_engine(target)
    scanned_files = len({f["file"] for f in raw_findings}) if raw_findings else 0

    print(f"[Permi] Engine found {len(raw_findings)} raw finding(s) "
          f"across {scanned_files} file(s)\n")

    # ── 5. Save every raw finding to DB ───────────────────────────────────────
    for finding in raw_findings:
        finding_id = save_finding(conn, scan_id, finding)
        finding["id"] = finding_id   # attach DB id so filter can update it

    conn.close()

    # ── 6. Run AI filter ──────────────────────────────────────────────────────
    # filter.py opens its own connection to update ai_verdict per finding
    real_findings = run_filter(raw_findings, offline=offline)

    # ── 7. Finish scan record ─────────────────────────────────────────────────
    conn = get_connection()
    finish_scan(
        conn,
        scan_id=scan_id,
        total_files=scanned_files,
        total_findings=len(real_findings),   # only real findings count
    )
    update_last_scan(conn, project_id)
    conn.close()

    return real_findings


def print_results(findings: list[dict]) -> None:
    """Print findings as clean JSON."""
    clean = [
        {k: v for k, v in f.items() if v is not None}
        for f in findings
    ]
    print(json.dumps(clean, indent=2))


def summary(findings: list[dict]) -> None:
    """Print a short summary line."""
    high   = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    low    = sum(1 for f in findings if f["severity"] == "low")

    print(f"[Permi] Done — "
          f"{len(findings)} real finding(s): "
          f"{high} high  {medium} medium  {low} low")
