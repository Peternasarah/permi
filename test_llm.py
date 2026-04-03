from ai_filter.llm_client import analyse

# A clear, unambiguous real vulnerability
test_finding = {
    "rule_id":      "SQL001",
    "rule_name":    "SQL Injection — string concatenation",
    "severity":     "high",
    "file":         "app/auth.py",
    "line_number":  8,
    "line_content": 'cursor.execute("SELECT * FROM users WHERE name = " + username)',
    "description":  "Raw string concatenation used to build a SQL query.",
}

result = analyse(test_finding)
print(f"Verdict     : {result['ai_verdict']}")
print(f"Explanation : {result['ai_explanation']}")
