#!/bin/sh
set -e

# ─── EndoriumFort Docker Entrypoint ─────────────────────────────────────
# Starts both the backend (C++) and Nginx (frontend + reverse proxy)

echo "╔══════════════════════════════════════════════╗"
echo "║  EndoriumFort — Privileged Access Management ║"
echo "╚══════════════════════════════════════════════╝"

# Ensure data directory is writable
cd /app/data

# Start backend in background
echo "[entrypoint] Starting backend on :8080..."
/app/bin/endoriumfort_backend &
BACKEND_PID=$!

# Wait for backend to be ready
echo "[entrypoint] Waiting for backend health..."
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8080/api/health >/dev/null 2>&1; then
    echo "[entrypoint] Backend is healthy"
    break
  fi
  if [ "$i" = "30" ]; then
    echo "[entrypoint] WARNING: Backend did not become healthy in 30s"
  fi
  sleep 1
done

# Start Nginx in foreground
echo "[entrypoint] Starting Nginx on :80..."
exec nginx -g "daemon off;" &
NGINX_PID=$!

# Handle shutdown gracefully
trap "echo '[entrypoint] Shutting down...'; kill $BACKEND_PID $NGINX_PID 2>/dev/null; wait" SIGTERM SIGINT

# Wait for either process to exit
wait -n $BACKEND_PID $NGINX_PID 2>/dev/null || true
echo "[entrypoint] Process exited, shutting down..."
kill $BACKEND_PID $NGINX_PID 2>/dev/null || true
wait
