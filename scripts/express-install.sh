#!/usr/bin/env bash
# LocalPwn express setup for Kali/Ubuntu; all privileged changes are opt-in.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSUME_YES=0
BUILD_DOCKER=0
RUN_TESTS=0
for arg in "$@"; do
    case "$arg" in
        --yes) ASSUME_YES=1 ;;
        --docker) BUILD_DOCKER=1 ;;
        --test) RUN_TESTS=1 ;;
        *) echo "Unknown argument: $arg" >&2; exit 2 ;;
    esac
done
if [[ "$(uname -s)" != "Linux" ]]; then
    echo 'Supported installer host: Kali/Ubuntu (including WSL2). Run inside Linux.' >&2
    exit 1
fi
say() { printf '\n[LocalPwn] %s\n' "$*"; }
ask() {
    if (( ASSUME_YES )); then return 0; fi
    local reply
    read -r -p "$1 [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]]
}
missing=()
command -v python3 >/dev/null || missing+=(python3)
if ! (command -v python3 >/dev/null && python3 -m venv --help >/dev/null 2>&1); then
    missing+=(python3-venv)
fi
command -v nmap >/dev/null || missing+=(nmap)
if ((${#missing[@]})); then
    say "Missing APT prerequisites: ${missing[*]}"
    if ask 'Run sudo apt update and install these packages?'; then
        sudo apt update
        sudo apt install -y "${missing[@]}"
    else
        say 'Cannot finish without the prerequisites.'
        exit 1
    fi
fi
say "Installing LocalPwn from $ROOT into .venv"
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip
"$ROOT/.venv/bin/python" -m pip install -e "$ROOT[full]"
if (( RUN_TESTS )); then
    "$ROOT/.venv/bin/python" -m pip install -e "$ROOT[test]"
    ( cd "$ROOT" && "$ROOT/.venv/bin/python" -m pytest -q )
fi
if (( BUILD_DOCKER )); then
    if ! command -v docker >/dev/null; then
        say 'Docker is not installed; install Docker Engine separately and re-run --docker.'
        exit 1
    fi
    if ask 'Build the optional Docker Nmap worker image (requires Docker permissions)?'; then
        docker build -t localpwn-scanner:1.0 -f "$ROOT/docker/Dockerfile.scanner" "$ROOT/docker"
    fi
fi
say 'Installation complete.'
printf '\nRun these commands:\n  cd %s\n  .venv/bin/localpwn doctor\n  .venv/bin/localpwn web\n' "$ROOT"
echo 'Dashboard: http://127.0.0.1:8000 (accessible only from the Kali host).'
echo 'No cloud AI key is configured or charged by this installer.'
