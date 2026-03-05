#!/bin/sh
set -e

# ─── EndoriumFort Docker Entrypoint ─────────────────────────────────────
# Starts both the backend (C++) and Nginx (frontend + reverse proxy)

echo "╔══════════════════════════════════════════════╗"
echo "║  EndoriumFort — Privileged Access Management ║"
echo "╚══════════════════════════════════════════════╝"

# Ensure data directory is writable
cd /app/data

TLS_CERT_PATH="${TLS_CERT_PATH:-/app/data/certs/tls.crt}"
TLS_KEY_PATH="${TLS_KEY_PATH:-/app/data/certs/tls.key}"
TLS_CERT_DIR="$(dirname "$TLS_CERT_PATH")"

mkdir -p "$TLS_CERT_DIR"

if [ ! -f "$TLS_CERT_PATH" ] || [ ! -f "$TLS_KEY_PATH" ]; then
  echo "[entrypoint] No TLS certificate found, generating self-signed cert..."
  if ! openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$TLS_KEY_PATH" \
    -out "$TLS_CERT_PATH" \
    -days "${TLS_SELF_SIGNED_DAYS:-365}" \
    -subj "${TLS_SUBJECT:-/C=FR/ST=IDF/L=Paris/O=EndoriumFort/OU=Ops/CN=localhost}"; then
    echo "[entrypoint] ERROR: Failed to generate TLS certificate at $TLS_CERT_PATH"
    echo "[entrypoint] Check write permissions or mount valid cert/key via TLS_CERT_PATH and TLS_KEY_PATH"
    exit 1
  fi
  echo "[entrypoint] Self-signed TLS certificate generated at $TLS_CERT_PATH"
fi

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
echo "[entrypoint] Starting Nginx on :443 (TLS) and :80 (redirect)..."
nginx -g "daemon off;" &
NGINX_PID=$!

# Wait for either process to exit
wait "$BACKEND_PID" "$NGINX_PID" 2>/dev/null || true
echo "[entrypoint] Process exited, shutting down..."
kill "$BACKEND_PID" "$NGINX_PID" 2>/dev/null || true
wait
