#!/bin/sh
set -e

# ─── EndoriumFort Docker Entrypoint ─────────────────────────────────────
# Starts both the backend (C++) and Nginx (frontend + reverse proxy)

echo "╔══════════════════════════════════════════════╗"
echo "║  EndoriumFort — Privileged Access Management ║"
echo "╚══════════════════════════════════════════════╝"

# Ensure data directory is writable
cd /app/data

# Handle shutdown gracefully
shutdown() {
  echo "[entrypoint] Shutting down..."
  kill "$BACKEND_PID" "$NGINX_PID" 2>/dev/null || true
  wait
  exit 0
}
trap shutdown TERM INT

# Start backend in background
echo "[entrypoint] Starting backend on :8080..."
/app/bin/endoriumfort_backend &
BACKEND_PID=$!

# Wait for backend to be ready
echo "[entrypoint] Waiting for backend health..."
i=0
while [ "$i" -lt 30 ]; do
  if curl -sf http://127.0.0.1:8080/api/health >/dev/null 2>&1; then
    echo "[entrypoint] Backend is healthy"
    break
  fi
  i=$((i + 1))
  if [ "$i" = "30" ]; then
    echo "[entrypoint] WARNING: Backend did not become healthy in 30s"
  fi
  sleep 1
done

# Start Nginx in background
echo "[entrypoint] Starting Nginx on :80..."
nginx -g "daemon off;" &
NGINX_PID=$!

# Wait for either process to exit
wait "$BACKEND_PID" "$NGINX_PID" 2>/dev/null || true
echo "[entrypoint] Process exited, shutting down..."
kill "$BACKEND_PID" "$NGINX_PID" 2>/dev/null || true
wait
