#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info() {
  printf "\n==> %s\n" "$1"
}

info "Building backend"
cmake -S "$ROOT_DIR/backend" -B "$ROOT_DIR/backend/build"
cmake --build "$ROOT_DIR/backend/build"

info "Building frontend"
cd "$ROOT_DIR/frontend"
NPM_PATH="$(command -v npm || true)"
if [[ -z "$NPM_PATH" ]]; then
  echo "npm not found. Install Node.js/npm inside WSL." >&2
  exit 1
fi
if [[ "$NPM_PATH" == /mnt/* ]]; then
  echo "Detected Windows npm at $NPM_PATH. Use the Linux npm in WSL to avoid UNC path issues." >&2
  echo "Try: sudo apt update && sudo apt install nodejs npm" >&2
  exit 1
fi
if [[ ! -d node_modules ]]; then
  npm install
fi
npm run build

info "Building EndoriumFortAgent"
cd "$ROOT_DIR/agent"
GO_PATH="$(command -v go || true)"
if [[ -z "$GO_PATH" ]]; then
  echo "go not found. Install Go to build the agent." >&2
  echo "Agent build skipped."
else
  go build -o endoriumfort-agent .
  echo "Agent binary: $ROOT_DIR/agent/endoriumfort-agent"
fi

info "Build completed"
