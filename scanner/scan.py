# scanner/scan.py
# The top-level scan coordinator.
# Ties together the rule engine (scanner/engine.py)
# and the database (db/queries.py) into one complete scan flow.

import json
from pathlib import Path

from scanner.engine import scan_directory as run_engine
from db.database import init_db, get_connection
from db.queries import (
    create_project,
    start_scan,
    save_finding,
    finish_scan,
    update_last_scan,
    get_findings_for_scan,
)


def scan(path: str, project_name: str = None) -> list[dict]:
    """
    Full scan pipeline:
      1. Resolve the path
      2. Create or find the project in the DB
      3. Start a scan record
      4. Run the rule engine over all files
      5. Save every finding to the DB
      6. Mark the scan complete
      7. Return all findings

    Args:
        path:         Local directory path to scan.
        project_name: Optional name. Defaults to the folder name.

    Returns:
        List of finding dicts, ordered by severity then file.
    """
    # ── 1. Resolve path ───────────────────────────────────────────────────────
    target = Path(path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Path does not exist: {target}")
    if not target.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {target}")

    name = project_name or target.name

    # ── 2. Initialise DB and create project ───────────────────────────────────
    init_db()
    conn = get_connection()

    project_id = create_project(conn, name=name, path=str(target))

    # ── 3. Start scan record ──────────────────────────────────────────────────
    scan_id = start_scan(conn, project_id)

    print(f"\n[Permi] Scanning: {target}")
    print(f"[Permi] Project : {name}  (id={project_id})")
    print(f"[Permi] Scan    : id={scan_id}\n")

    # ── 4. Run the engine ─────────────────────────────────────────────────────
    raw_findings = run_engine(target)

    # Count unique files scanned
    scanned_files = len({f["file"] for f in raw_findings}) if raw_findings else 0

    # ── 5. Save every finding ─────────────────────────────────────────────────
    for finding in raw_findings:
        save_finding(conn, scan_id, finding)

    # ── 6. Finish scan record ─────────────────────────────────────────────────
    finish_scan(
        conn,
        scan_id=scan_id,
        total_files=scanned_files,
        total_findings=len(raw_findings),
    )
    update_last_scan(conn, project_id)

    # ── 7. Return findings from DB (ordered by severity) ──────────────────────
    results = get_findings_for_scan(conn, scan_id)
    conn.close()

    return results


def print_results(findings: list[dict]) -> None:
    """
    Print findings as clean JSON to the terminal.
    This is the raw Phase 0 output — Phase 2 adds
    a human-readable coloured format.
    """
    # Strip fields that are None to keep output clean
    clean = [
        {k: v for k, v in f.items() if v is not None}
        for f in findings
    ]
    print(json.dumps(clean, indent=2))


def summary(findings: list[dict]) -> None:
    """
    Print a short summary line after the full JSON output.
    """
    high   = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    low    = sum(1 for f in findings if f["severity"] == "low")

    print(f"\n[Permi] Done — "
          f"{len(findings)} finding(s): "
          f"{high} high  {medium} medium  {low} low")
