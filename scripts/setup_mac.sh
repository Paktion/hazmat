#!/usr/bin/env bash
# One-time setup for Hazmat on macOS (Apple Silicon or Intel).
# Run from the repo root:  ./scripts/setup_mac.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required: https://brew.sh" >&2
  exit 1
fi

echo "==> Installing system tools (python, yara, ghidra)"
brew install python@3.12 yara
brew install ghidra || true                 # formula; pulls in its own OpenJDK

# Put Ghidra's headless analyzer on PATH for this shell and future ones.
GHIDRA_PREFIX="$(brew --prefix ghidra 2>/dev/null || true)"
GHIDRA_HEADLESS="$(ls -d "$GHIDRA_PREFIX"/libexec/support/analyzeHeadless "$GHIDRA_PREFIX"/libexec/*/support/analyzeHeadless 2>/dev/null | head -1 || true)"
if [ -n "$GHIDRA_HEADLESS" ]; then
  mkdir -p "$HOME/.local/bin"
  ln -sf "$GHIDRA_HEADLESS" "$HOME/.local/bin/analyzeHeadless"
  echo "    linked analyzeHeadless -> $HOME/.local/bin (make sure it's on your PATH)"
fi

echo "==> Creating virtualenv and installing Hazmat"
python3.12 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[analysis,modal]"

if [ ! -f .env ]; then
  cp .env.example .env
  echo "==> Created .env from .env.example — fill in your keys next."
fi

mkdir -p samples reports
cat <<'EOF'

Done. Next:
  1. Fill in .env:
       MODEL_API_KEY   -> dev.meta.ai > API keys > Create
       BASETEN_API_KEY -> one-time link in Baseten's "Your Baseten API key is ready" email
                          Open it ONCE, paste here.
  2. modal setup        (optional; saves a Modal token to ~/.modal.toml)
  3. source .venv/bin/activate && hazmat check
EOF
