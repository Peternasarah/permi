from pathlib import Path
from scanner.engine import scan_file

findings = scan_file(Path('test_vuln.py'))
for f in findings:
    print(f['rule_id'], '|', f['severity'], '|', 'line', f['line_number'], '|', f['rule_name'])
