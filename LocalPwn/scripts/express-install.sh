#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" != "Linux" ]]; then echo 'Use Kali Linux, Ubuntu, or WSL2.' >&2; exit 1; fi
if ! command -v python3 >/dev/null || ! python3 -m venv --help >/dev/null 2>&1; then
  echo 'Python 3 with venv is required; on Kali: sudo apt install python3 python3-venv' >&2; exit 1
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo 'LocalPwn express setup (no automatic sudo changes)'
echo 'Optional network scanner: sudo apt install nmap'
read -r -p 'Create/update a project-local Python virtual environment? [y/N] ' response
[[ "$response" =~ ^[Yy]$ ]] || exit 0
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip
"$ROOT/.venv/bin/python" -m pip install -e "$ROOT[web]"
printf '\nReady. Run: %s/.venv/bin/localpwn doctor\n' "$ROOT"
printf 'Dashboard: %s/.venv/bin/localpwn web\n' "$ROOT"
