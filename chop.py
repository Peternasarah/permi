from pathlib import Path
from scanner.engine import scan_file
from scanner.rules import SCANNABLE_EXTENSIONS

path = Path(r'C:\Users\dashe\Downloads\PCare_Phase3_Complete\PCare_Phase3')
py_files = list(path.rglob('*.py'))
print(f'Found {len(py_files)} .py files')
for f in py_files[:5]:
    print(f'  Scanning: {f.name}')
    results = scan_file(f)
    print(f'  Findings: {len(results)}')
    if results:
        print(f'  First finding: {results[0]["rule_id"]}')

