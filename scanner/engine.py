# scanner/engine.py
# The engine takes a file path, reads it line by line,
# and tests every line against every rule in RULES.
# Returns a list of finding dictionaries.

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
        # If the file can't be read for any reason, skip it silently
        return findings

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):
        for rule in RULES:
            if rule["pattern"].search(line):
                findings.append({
                    "rule_id":     rule["id"],
                    "rule_name":   rule["name"],
                    "severity":    rule["severity"],
                    "description": rule["description"],
                    "file":        str(file_path),
                    "line_number": line_number,
                    "line_content": line.strip(),
                    "ai_verdict":  None,   # filled in Phase 1
                    "ai_explanation": None, # filled in Phase 1
                })

    return findings


def scan_directory(directory: Path) -> list[dict]:
    """
    Recursively walk a directory, scan every eligible file,
    and return all findings combined.
    """
    all_findings = []
    directory = Path(directory).resolve()

    for file_path in directory.rglob("*"):

        # Skip any path that passes through a blocked directory
        if any(skip in file_path.parts for skip in SKIP_DIRS):
            continue

        # Skip directories themselves — only process files
        if not file_path.is_file():
            continue

        findings = scan_file(file_path)
        all_findings.extend(findings)

    return all_findings
