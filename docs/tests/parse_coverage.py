import json
import sys
from pathlib import Path

if len(sys.argv) > 1:
    coverage_path = sys.argv[1]
else:
    script_dir = Path(__file__).resolve().parent
    coverage_path = str(script_dir / 'coverage' / 'coverage.json')

with open(coverage_path, 'r') as f:
    d = json.load(f)

files = d.get('files', [])
total_lines = 0
total_covered = 0
total_functions = 0
func_covered = 0

for f in files:
    fname = f.get('file', 'unknown')
    lines = f.get('lines', [])
    functions = f.get('functions', [])

    file_lines = 0
    file_covered = 0
    for ln in lines:
        file_lines += 1
        if ln.get('count', 0) > 0:
            file_covered += 1

    file_funcs = len(functions)
    file_funcs_covered = sum(1 for fn in functions if fn.get('execution_count', 0) > 0)

    pct = (file_covered / file_lines * 100) if file_lines > 0 else 0
    func_pct = (file_funcs_covered / file_funcs * 100) if file_funcs > 0 else 0

    print(f"{fname}")
    print(f"  Lines: {file_covered}/{file_lines} ({pct:.1f}%)")
    print(f"  Funcs: {file_funcs_covered}/{file_funcs} ({func_pct:.1f}%)")

    total_lines += file_lines
    total_covered += file_covered
    total_functions += file_funcs
    func_covered += file_funcs_covered

print(f"\nTotal Lines: {total_covered}/{total_lines} ({(total_covered/total_lines*100) if total_lines > 0 else 0:.1f}%)")
print(f"Total Funcs: {func_covered}/{total_functions} ({(func_covered/total_functions*100) if total_functions > 0 else 0:.1f}%)")
