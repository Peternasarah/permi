# scanner/engine.py
# The engine takes a file path, reads it line by line,
# and tests every line against every rule in RULES.
# Returns a list of finding dictionaries.

from __future__ import annotations
from pathlib import Path
from .rules import RULES, SCANNABLE_EXTENSIONS, SKIP_DIRS


def scan_file(file_path: Path) -> list[dict]:
    """
    Scan a single file against all rules.
    Returns a list of findings (may be empty).
    """
    findings = []

    # Skip files with extensions we don't handle
    if file_path.suffix.lower() not in SCANNABLE_EXTENSIONS:
        return findings

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):
        for rule in RULES:
            if rule["pattern"].search(line):
                findings.append({
                    "rule_id":        rule["id"],
                    "rule_name":      rule["name"],
                    "severity":       rule["severity"],
                    "description":    rule["description"],
                    "file":           str(file_path),
                    "line_number":    line_number,
                    "line_content":   line.strip(),
                    "ai_verdict":     None,
                    "ai_explanation": None,
                })

    return findings


def scan_directory(directory: Path) -> list[dict]:
    """
    Recursively walk a directory, scan every eligible file,
    and return all findings combined.

    SKIP_DIRS check is case-insensitive so it works correctly
    on both Windows (case-insensitive FS) and Linux.
    """
    all_findings = []
    directory    = Path(directory).resolve()

    # Lowercase skip set for case-insensitive comparison
    skip_lower = {s.lower() for s in SKIP_DIRS}

    for file_path in directory.rglob("*"):

        # Skip any path that passes through a blocked directory
        # Uses lower() for Windows compatibility
        path_parts_lower = [p.lower() for p in file_path.parts]
        if any(skip in path_parts_lower for skip in skip_lower):
            continue

        # Skip directories themselves — only process files
        if not file_path.is_file():
            continue

        findings = scan_file(file_path)
        all_findings.extend(findings)

    return all_findings
