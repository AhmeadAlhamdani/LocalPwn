#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
echo 'Update source code through Git first, then reinstall dependencies.'
echo 'If this checkout has local changes, commit or stash them before git pull.'
if [[ -d .venv ]]; then
  .venv/bin/python -m pip install -e '.[full]'
else
  bash scripts/express-install.sh
fi
.venv/bin/localpwn doctor
