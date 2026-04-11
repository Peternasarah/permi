# scanner/scan.py
# Full scan pipeline — engine + AI filter combined.
# Supports local directories and GitHub URLs.

from __future__ import annotations
import tempfile
import subprocess
from pathlib import Path
from colorama import Fore, Style

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
    p = path.strip().strip('"').strip("'")
    return p.startswith("https://github.com/") or p.startswith("git@github.com:")


def _clone_repo(url: str, target_dir: Path) -> None:
    print(f"{Fore.CYAN}[Permi] Cloning  : {url}{Style.RESET_ALL}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", url, str(target_dir)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed:\n{result.stderr.strip()}")
    print(f"{Fore.CYAN}[Permi] Cloned to: {target_dir}{Style.RESET_ALL}\n")


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
    from scanner.rules import SCANNABLE_EXTENSIONS

    # ── Normalise path ────────────────────────────────────────────────────────
    path      = path.strip().strip('"').strip("'")
    is_github = _is_github_url(path)

    # ── GitHub URL — clone to a temp directory ────────────────────────────────
    if is_github:
        tmp          = tempfile.TemporaryDirectory()
        target       = Path(tmp.name) / "repo"
        _clone_repo(path, target)
        default_name = path.rstrip("/").split("/")[-1].replace(".git", "")
    else:
        tmp    = None
        target = Path(path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Path does not exist: {target}")
        if not target.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {target}")
        default_name = target.name

    name = project_name or default_name

    # ── Init DB and create/find project ───────────────────────────────────────
    init_db()
    conn       = get_connection()
    project_id = create_project(conn, name=name, path=str(target))
    scan_id    = start_scan(conn, project_id)

    print(f"{Fore.CYAN}[Permi] Scanning : {target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[Permi] Project  : {name}  (id={project_id}){Style.RESET_ALL}")
    print(f"{Fore.CYAN}[Permi] Scan     : id={scan_id}{Style.RESET_ALL}\n")

    # ── Run the engine ────────────────────────────────────────────────────────
    raw_findings  = run_engine(target)
    raw_count     = len(raw_findings)
    scanned_files = len({f["file"] for f in raw_findings}) if raw_findings else 0

    # ── Warn clearly if nothing was scanned ───────────────────────────────────
    if scanned_files == 0:
        # Count total files in directory to distinguish empty project vs wrong extensions
        all_files = [f for f in target.rglob("*") if f.is_file()]
        ext_found = {f.suffix.lower() for f in all_files if f.suffix}

        print(
            f"{Fore.YELLOW}[Permi] Warning: 0 files matched scannable extensions.{Style.RESET_ALL}"
        )

        if not all_files:
            print(
                f"{Fore.YELLOW}[Permi] The directory appears to be empty.{Style.RESET_ALL}\n"
            )
        else:
            unsupported = ext_found - SCANNABLE_EXTENSIONS
            supported   = ext_found & SCANNABLE_EXTENSIONS

            if supported:
                print(
                    f"{Fore.YELLOW}[Permi] Found {len(all_files)} file(s) but none matched "
                    f"scannable extensions in this path.\n"
                    f"[Permi] Supported extensions found: "
                    f"{', '.join(sorted(supported))}{Style.RESET_ALL}"
                )
            else:
                print(
                    f"{Fore.YELLOW}[Permi] Found {len(all_files)} file(s) with extensions: "
                    f"{', '.join(sorted(unsupported)[:10])}\n"
                    f"[Permi] None of these are currently supported by Permi's scanner.\n"
                    f"[Permi] Supported: .py .js .ts .java .php .dart .kt .swift .go "
                    f".rb .html .vue .env .yml and more.\n"
                    f"[Permi] Open an issue at github.com/Peternasarah/permi to request "
                    f"support for your language.{Style.RESET_ALL}\n"
                )
    else:
        print(
            f"{Fore.WHITE}[Permi] Engine found {raw_count} raw finding(s) "
            f"across {scanned_files} file(s){Style.RESET_ALL}\n"
        )

    # ── Save every raw finding to DB ──────────────────────────────────────────
    for finding in raw_findings:
        finding_id    = save_finding(conn, scan_id, finding)
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
        print(f"{Fore.CYAN}[Permi] Temp clone deleted.{Style.RESET_ALL}\n")

    return real_findings, raw_count
