#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_BUILD_DIR="$ROOT_DIR/backend/build"
BACKEND_BIN="$BACKEND_BUILD_DIR/endoriumfort_backend"
FRONTEND_DIR="$ROOT_DIR/frontend"

is_wsl() {
  grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null
}

cpu_cores() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  elif command -v getconf >/dev/null 2>&1; then
    getconf _NPROCESSORS_ONLN
  else
    echo 2
  fi
}

CORES="$(cpu_cores)"
if [[ ! "$CORES" =~ ^[0-9]+$ ]] || [[ "$CORES" -lt 1 ]]; then
  CORES=2
fi

DEFAULT_BUILD_JOBS="$CORES"
if is_wsl; then
  DEFAULT_BUILD_JOBS=2
fi

BUILD_JOBS="${ENDORIUMFORT_BUILD_JOBS:-$DEFAULT_BUILD_JOBS}"
if [[ ! "$BUILD_JOBS" =~ ^[0-9]+$ ]] || [[ "$BUILD_JOBS" -lt 1 ]]; then
  echo "Invalid ENDORIUMFORT_BUILD_JOBS='$BUILD_JOBS' (must be integer >= 1)" >&2
  exit 1
fi

BUILD_TESTING="${ENDORIUMFORT_BUILD_TESTING:-OFF}"
case "$BUILD_TESTING" in
  ON|OFF) ;;
  *)
    echo "Invalid ENDORIUMFORT_BUILD_TESTING='$BUILD_TESTING' (use ON or OFF)" >&2
    exit 1
    ;;
esac

BACKEND_PORT="${ENDORIUMFORT_PORT:-8080}"
FRONTEND_PORT="${ENDORIUMFORT_FRONTEND_PORT:-5173}"

BACKEND_PID=""
FRONTEND_PID=""

info() {
  printf "\n\033[1;36m==> %s\033[0m\n" "$1"
}

cleanup() {
  local code=$?
  if [[ -n "$FRONTEND_PID" ]] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
    kill "$FRONTEND_PID" 2>/dev/null || true
  fi
  if [[ -n "$BACKEND_PID" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  wait >/dev/null 2>&1 || true
  exit "$code"
}
trap cleanup INT TERM EXIT

ensure_backend() {
  if [[ -x "$BACKEND_BIN" ]]; then
    return
  fi

  info "Backend binary missing - building backend"
  cmake -S "$ROOT_DIR/backend" -B "$BACKEND_BUILD_DIR" -DBUILD_TESTING="$BUILD_TESTING"
  cmake --build "$BACKEND_BUILD_DIR" --parallel "$BUILD_JOBS"
}

ensure_frontend_deps() {
  if ! command -v npm >/dev/null 2>&1; then
    echo "npm is required to run the frontend dev server." >&2
    exit 1
  fi

  if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
    info "Installing frontend dependencies"
    (cd "$FRONTEND_DIR" && npm install)
  fi
}

start_backend() {
  info "Starting backend on http://localhost:${BACKEND_PORT}"
  (
    cd "$BACKEND_BUILD_DIR"
    ENDORIUMFORT_PORT="$BACKEND_PORT" ./endoriumfort_backend
  ) &
  BACKEND_PID=$!
}

start_frontend() {
  info "Starting frontend on http://localhost:${FRONTEND_PORT}"
  (
    cd "$FRONTEND_DIR"
    npm run dev -- --host 0.0.0.0 --port "$FRONTEND_PORT"
  ) &
  FRONTEND_PID=$!
}

main() {
  ensure_backend
  ensure_frontend_deps

  start_backend
  start_frontend

  info "Dev stack ready"
  echo "Backend : http://localhost:${BACKEND_PORT}"
  echo "Frontend: http://localhost:${FRONTEND_PORT}"
  echo "Press Ctrl+C to stop both processes."

  wait -n "$BACKEND_PID" "$FRONTEND_PID"
}

main "$@"
