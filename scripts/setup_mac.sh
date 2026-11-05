#!/usr/bin/env bash
# One-time setup for Hazmat on macOS (Apple Silicon or Intel). Linux works the same
# minus Homebrew. Run from the repo root:  ./scripts/setup_mac.sh
#
# The analysis tools (Ghidra, capa, FLOSS, YARA) live in the sandbox image, not on
# your machine. You need Python 3.11+ and either Docker (local sandbox) or a Modal
# account (cloud sandbox), or both.
set -euo pipefail
cd "$(dirname "$0")/.."

PY=$(command -v python3.12 || command -v python3.13 || command -v python3.11 || true)
if [ -z "$PY" ]; then
  if command -v brew >/dev/null 2>&1; then brew install python@3.12; PY=$(command -v python3.12); else
    echo "Python 3.11+ is required" >&2; exit 1; fi
fi

echo "==> Creating virtualenv and installing Hazmat"
"$PY" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -e ".[modal,dev]"

if [ ! -f .env ]; then
  cp .env.example .env
  echo "==> Created .env from .env.example; fill in your keys next."
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  echo "==> Building the sandbox image for local runs (first time: ~10-20 minutes, ~3 GB)"
  docker build --platform linux/amd64 -t hazmat-sandbox sandbox/
  echo "==> Building the harmless test samples (in a container)"
  ./testdata/build.sh
else
  echo "==> Docker not running: skipping the local image and test samples."
  echo "    Start Docker and rerun, or use Modal (modal setup) and build samples later with ./testdata/build.sh"
fi

cat <<'MSG'

Done. Next:
  1. Fill in .env: MODEL_API_KEY (dev.meta.ai), BASETEN_API_KEY, FIREWORKS_API_KEY
  2. source .venv/bin/activate
  3. hazmat check                                  # each provider answers; keys never printed
  4. hazmat selftest --backend docker              # every tool on every test sample
  5. hazmat analyze testdata/bin/stealer_sim_poisoned.exe --backend docker
Optional: modal setup, then drop --backend docker to use a Modal sandbox instead.
MSG
