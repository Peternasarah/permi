from db.database import init_db, get_connection
from db.queries import create_project, start_scan, save_finding, finish_scan, get_findings_for_scan

# Step 1 — initialise the database (creates permi.db)
init_db()

# Step 2 — create a test project
conn = get_connection()
project_id = create_project(conn, name="test-project", path="C:/test/myapp")
print(f"Project ID: {project_id}")

# Step 3 — start a scan
scan_id = start_scan(conn, project_id)
print(f"Scan ID: {scan_id}")

# Step 4 — save a dummy finding
save_finding(conn, scan_id, {
    "rule_id":      "SQL001",
    "rule_name":    "SQL Injection — string concatenation",
    "severity":     "high",
    "description":  "Raw string concatenation in SQL query.",
    "file":         "app/views.py",
    "line_number":  42,
    "line_content": 'cursor.execute("SELECT * FROM users WHERE name = " + name)',
    "ai_verdict":   None,
    "ai_explanation": None,
})

# Step 5 — finish the scan
finish_scan(conn, scan_id, total_files=10, total_findings=1)

# Step 6 — read it back
findings = get_findings_for_scan(conn, scan_id)
print(f"\nFindings saved: {len(findings)}")
for f in findings:
    print(f"  {f['rule_id']} | {f['severity']} | line {f['line_number']} | {f['file']}")

conn.close()
