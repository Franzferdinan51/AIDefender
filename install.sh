#!/usr/bin/env bash
set -euo pipefail
# AIDefender installer for macOS and Linux.
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required (3.9+)." >&2
  exit 1
fi

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
.venv/bin/python -m pip install -e ".[full]" || echo "(optional deps skipped)"

echo ""
echo "Installed. Run with:"
echo "  source .venv/bin/activate"
echo "  aidefender status"
echo "  aidefender scan ~/Downloads"
