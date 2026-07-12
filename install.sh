#!/usr/bin/env bash
# Installs INCLUDED and makes the `included` command available.
#
# Prefers pipx (isolated, no virtualenv to manage yourself). Falls back to
# a local .venv/ if pipx isn't installed.
set -euo pipefail

REQUIRED_MAJOR=3
REQUIRED_MINOR=10

info() { printf '\033[1;36m[*]\033[0m %s\n' "$1"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$1"; }
fail() { printf '\033[1;31m[-]\033[0m %s\n' "$1" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || fail "python3 not found. Install Python ${REQUIRED_MAJOR}.${REQUIRED_MINOR}+ first."

py_version=$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
py_major=${py_version%%.*}
py_minor=${py_version##*.}
if [ "$py_major" -lt "$REQUIRED_MAJOR" ] || { [ "$py_major" -eq "$REQUIRED_MAJOR" ] && [ "$py_minor" -lt "$REQUIRED_MINOR" ]; }; then
    fail "Python ${REQUIRED_MAJOR}.${REQUIRED_MINOR}+ required, found ${py_version}."
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

if command -v pipx >/dev/null 2>&1; then
    info "pipx found — installing INCLUDED as an isolated CLI tool"
    pipx install --force .
    ok "Installed. Verifying..."
    included --version
    ok "Ready. Run: included --help"
else
    info "pipx not found — installing into a local virtualenv (.venv)"
    python3 -m venv .venv
    .venv/bin/pip install --quiet --upgrade pip
    .venv/bin/pip install --quiet -e .
    ok "Installed. Verifying..."
    .venv/bin/included --version
    ok "Ready."
    echo
    echo "Run it with:"
    echo "    .venv/bin/included --help"
    echo "or activate the virtualenv first:"
    echo "    source .venv/bin/activate && included --help"
fi

echo
echo "For authorized security testing only."
