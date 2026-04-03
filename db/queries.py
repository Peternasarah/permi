# db/queries.py
# All database read/write functions used by the scanner.
# Every function takes a connection as its first argument
# so the caller controls when to open and close it.

from datetime import datetime


def create_project(conn, name: str, path: str) -> int:
    """
    Insert a new project and return its ID.
    If a project with the same path already exists, return its ID instead.
    """
    existing = conn.execute(
        "SELECT id FROM projects WHERE path = ?", (path,)
    ).fetchone()

    if existing:
        return existing["id"]

    cursor = conn.execute(
        "INSERT INTO projects (name, path) VALUES (?, ?)",
        (name, path)
    )
    conn.commit()
    return cursor.lastrowid


def start_scan(conn, project_id: int) -> int:
    """
    Create a new scan_results row with status 'running'.
    Returns the scan ID.
    """
    cursor = conn.execute(
        "INSERT INTO scan_results (project_id, status) VALUES (?, 'running')",
        (project_id,)
    )
    conn.commit()
    return cursor.lastrowid


def finish_scan(conn, scan_id: int, total_files: int, total_findings: int) -> None:
    """
    Mark a scan as completed and record the final counts.
    """
    conn.execute("""
        UPDATE scan_results
        SET status          = 'completed',
            finished_at     = datetime('now'),
            total_files     = ?,
            total_findings  = ?
        WHERE id = ?
    """, (total_files, total_findings, scan_id))

    conn.commit()


def save_finding(conn, scan_id: int, finding: dict) -> int:
    """
    Insert one finding into the findings table.
    Returns the new finding's ID.
    """
    cursor = conn.execute("""
        INSERT INTO findings (
            scan_id, rule_id, rule_name, severity, description,
            file, line_number, line_content, ai_verdict, ai_explanation
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        finding["rule_id"],
        finding["rule_name"],
        finding["severity"],
        finding["description"],
        finding["file"],
        finding["line_number"],
        finding["line_content"],
        finding.get("ai_verdict"),
        finding.get("ai_explanation"),
    ))
    conn.commit()
    return cursor.lastrowid


def get_findings_for_scan(conn, scan_id: int) -> list:
    """
    Retrieve all findings for a given scan, ordered by severity then file.
    """
    rows = conn.execute("""
        SELECT * FROM findings
        WHERE scan_id = ?
        ORDER BY
            CASE severity
                WHEN 'high'   THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low'    THEN 3
                ELSE 4
            END,
            file, line_number
    """, (scan_id,)).fetchall()

    return [dict(row) for row in rows]


def update_last_scan(conn, project_id: int) -> None:
    """
    Update the last_scan timestamp on a project after a scan completes.
    """
    conn.execute(
        "UPDATE projects SET last_scan = datetime('now') WHERE id = ?",
        (project_id,)
    )
    conn.commit()
