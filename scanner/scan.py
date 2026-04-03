# scanner/scan.py
# Full scan pipeline — engine + AI filter combined.
# Supports local directories and GitHub URLs.

import tempfile
import subprocess
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
)


def _is_github_url(path: str) -> bool:
    """Return True if the path looks like a GitHub URL."""
    p = path.strip().strip('"').strip("'")
    return p.startswith("https://github.com/") or p.startswith("git@github.com:")


def _clone_repo(url: str, target_dir: Path) -> None:
    """
    Clone a GitHub repo into target_dir.
    Raises RuntimeError if git is not installed or the clone fails.
    """
    print(f"[Permi] Cloning  : {url}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", url, str(target_dir)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed:\n{result.stderr.strip()}")
    print(f"[Permi] Cloned to: {target_dir}\n")


def scan(
    path: str,
    project_name: str = None,
    offline: bool = False,
) -> tuple[list[dict], int]:
    """
    Full scan pipeline.

    Returns:
        (real_findings, raw_count)
        real_findings — findings the AI marked as REAL
        raw_count     — total before AI filtering (for accurate summary)
    """
    # ── Normalise path ────────────────────────────────────────────────────────
    path = path.strip().strip('"').strip("'")
    is_github = _is_github_url(path)

    # ── GitHub URL — clone to a temp directory ────────────────────────────────
    if is_github:
        tmp = tempfile.TemporaryDirectory()
        target = Path(tmp.name) / "repo"
        _clone_repo(path, target)
        default_name = path.rstrip("/").split("/")[-1].replace(".git", "")
    else:
        tmp = None
        target = Path(path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Path does not exist: {target}")
        if not target.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {target}")
        default_name = target.name

    name = project_name or default_name

    # ── Init DB and create/find project ───────────────────────────────────────
    init_db()
    conn = get_connection()
    project_id = create_project(conn, name=name, path=str(target))

    # ── Start scan record ─────────────────────────────────────────────────────
    scan_id = start_scan(conn, project_id)

    print(f"[Permi] Scanning : {target}")
    print(f"[Permi] Project  : {name}  (id={project_id})")
    print(f"[Permi] Scan     : id={scan_id}\n")

    # ── Run the engine ────────────────────────────────────────────────────────
    raw_findings = run_engine(target)
    raw_count    = len(raw_findings)
    scanned_files = len({f["file"] for f in raw_findings}) if raw_findings else 0

    print(f"[Permi] Engine found {raw_count} raw finding(s) "
          f"across {scanned_files} file(s)\n")

    # ── Save every raw finding to DB ──────────────────────────────────────────
    for finding in raw_findings:
        finding_id = save_finding(conn, scan_id, finding)
        finding["id"] = finding_id

    conn.close()

    # ── Run AI filter ─────────────────────────────────────────────────────────
    real_findings = run_filter(raw_findings, offline=offline)

    # ── Finish scan record ────────────────────────────────────────────────────
    conn = get_connection()
    finish_scan(
        conn,
        scan_id=scan_id,
        total_files=scanned_files,
        total_findings=len(real_findings),
    )
    update_last_scan(conn, project_id)
    conn.close()

    # ── Clean up temp clone ───────────────────────────────────────────────────
    if tmp:
        tmp.cleanup()
        print("[Permi] Temp clone deleted.\n")

    return real_findings, raw_count
