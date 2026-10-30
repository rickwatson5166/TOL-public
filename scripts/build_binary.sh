#!/usr/bin/env bash
# Build a single-file `tol` executable (Linux). Needs: pip install pyinstaller
set -euo pipefail
cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"
printf 'import sys\nfrom tol_app.cli import main\nsys.exit(main())\n' > "$tmp/entry.py"
pyinstaller --onefile --name tol --distpath dist --workpath "$tmp/build" --specpath "$tmp" \
  --paths . --add-data "$PWD/tol_app/static:tol_app/static" --add-data "$PWD/tol_app/evidence_verify.py:tol_app" --add-data "$PWD/tol_app/timestamp.py:tol_app" "$tmp/entry.py"
echo "Built dist/tol"
