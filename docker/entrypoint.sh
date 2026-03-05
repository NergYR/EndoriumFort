#!/bin/sh
set -e

# ─── EndoriumFort Docker Entrypoint ─────────────────────────────────────
# Starts both the backend (C++) and Nginx (frontend + reverse proxy)

echo "╔══════════════════════════════════════════════╗"
echo "║  EndoriumFort — Privileged Access Management ║"
echo "╚══════════════════════════════════════════════╝"

# Ensure data directory is writable
cd /app/data

ACME_ENABLED="${ACME_ENABLED:-0}"
ACME_DOMAIN="${ACME_DOMAIN:-}"
ACME_EMAIL="${ACME_EMAIL:-}"

refresh_tls_from_letsencrypt() {
  domain="$1"
  src_dir="/etc/letsencrypt/live/$domain"
  if [ ! -f "$src_dir/fullchain.pem" ] || [ ! -f "$src_dir/privkey.pem" ]; then
    return 1
  fi
  cp "$src_dir/fullchain.pem" /etc/nginx/tls/tls.crt
  cp "$src_dir/privkey.pem" /etc/nginx/tls/tls.key
  chmod 644 /etc/nginx/tls/tls.crt
  chmod 600 /etc/nginx/tls/tls.key
  return 0
}

configure_acme() {
  if [ "$ACME_ENABLED" != "1" ]; then
    return
  fi

  if [ -z "$ACME_DOMAIN" ] || [ -z "$ACME_EMAIL" ]; then
    echo "[entrypoint] ACME_ENABLED=1 requires ACME_DOMAIN and ACME_EMAIL"
    exit 1
  fi

  echo "[entrypoint] ACME enabled for domain: $ACME_DOMAIN"
  mkdir -p /var/www/certbot /etc/letsencrypt

  if certbot certonly --webroot -w /var/www/certbot \
      -d "$ACME_DOMAIN" \
      --email "$ACME_EMAIL" \
      --agree-tos --non-interactive --keep-until-expiring; then
    if refresh_tls_from_letsencrypt "$ACME_DOMAIN"; then
      echo "[entrypoint] ACME certificate installed for $ACME_DOMAIN"
      nginx -s reload >/dev/null 2>&1 || true
    else
      echo "[entrypoint] ACME cert obtained but copy failed for domain $ACME_DOMAIN"
      exit 1
    fi
  else
    echo "[entrypoint] ACME issuance failed, keeping current certificate"
  fi

  (
    while true; do
      sleep 12h
      certbot renew --webroot -w /var/www/certbot --quiet \
        --deploy-hook "/bin/sh -c 'cp /etc/letsencrypt/live/$ACME_DOMAIN/fullchain.pem /etc/nginx/tls/tls.crt && cp /etc/letsencrypt/live/$ACME_DOMAIN/privkey.pem /etc/nginx/tls/tls.key && chmod 644 /etc/nginx/tls/tls.crt && chmod 600 /etc/nginx/tls/tls.key && nginx -s reload'" || true
    done
  ) &
  ACME_RENEW_PID=$!
}

# Handle shutdown gracefully
shutdown() {
  echo "[entrypoint] Shutting down..."
  kill "$BACKEND_PID" "$NGINX_PID" "$ACME_RENEW_PID" 2>/dev/null || true
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

configure_acme

# Wait for either process to exit
wait "$BACKEND_PID" "$NGINX_PID" 2>/dev/null || true
echo "[entrypoint] Process exited, shutting down..."
kill "$BACKEND_PID" "$NGINX_PID" 2>/dev/null || true
wait
