#!/usr/bin/env bash
# ─── EndoriumFort — Production Deployment Script ────────────────────────
# Deploys EndoriumFort on a Linux server with:
#   - Backend binary (C++ / Crow on port 8080)
#   - Frontend static files served by Nginx
#   - Nginx reverse proxy with TLS (Let's Encrypt or self-signed)
#   - systemd service for auto-start
#
# Usage:
#   sudo ./deploy-prod.sh [--domain bastion.example.com] [--no-tls] [--self-signed]
#
# Prerequisites (auto-installed if missing):
#   - nginx, certbot (for Let's Encrypt), sqlite3, libssh2
set -euo pipefail

# ─── Defaults ────────────────────────────────────────────────────────────
DOMAIN=""
TLS="letsencrypt"   # letsencrypt | self-signed | none
INSTALL_DIR="/opt/endoriumfort"
SERVICE_USER="endoriumfort"
BACKEND_PORT=8080

# ─── Parse arguments ────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)    DOMAIN="$2"; shift 2 ;;
    --no-tls)    TLS="none"; shift ;;
    --self-signed) TLS="self-signed"; shift ;;
    --port)      BACKEND_PORT="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: sudo $0 [--domain bastion.example.com] [--no-tls] [--self-signed] [--port 8080]"
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info()  { printf "\n\033[1;36m==> %s\033[0m\n" "$1"; }
warn()  { printf "\033[1;33m  ⚠  %s\033[0m\n" "$1"; }
ok()    { printf "\033[1;32m  ✓  %s\033[0m\n" "$1"; }
fail()  { printf "\033[1;31m  ✗  %s\033[0m\n" "$1"; exit 1; }

# ─── Root check ─────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  fail "This script must be run as root (sudo ./deploy-prod.sh ...)"
fi

# ─── Detect package manager ─────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
  PKG="apt"
elif command -v dnf &>/dev/null; then
  PKG="dnf"
elif command -v yum &>/dev/null; then
  PKG="yum"
else
  fail "No supported package manager found (apt/dnf/yum)"
fi

install_pkg() {
  case "$PKG" in
    apt) apt-get install -y "$@" ;;
    dnf) dnf install -y "$@" ;;
    yum) yum install -y "$@" ;;
  esac
}

# ─── Install system dependencies ────────────────────────────────────────
info "Installing system dependencies"
case "$PKG" in
  apt)
    apt-get update -qq
    install_pkg nginx sqlite3 libsqlite3-dev libssh2-1 openssl
    ;;
  dnf|yum)
    install_pkg nginx sqlite libsqlite3x-devel libssh2 openssl
    ;;
esac

if [[ "$TLS" == "letsencrypt" ]]; then
  install_pkg certbot python3-certbot-nginx 2>/dev/null || install_pkg certbot
fi
ok "Dependencies installed"

# ─── Create service user ────────────────────────────────────────────────
info "Setting up service user"
if ! id "$SERVICE_USER" &>/dev/null; then
  useradd --system --shell /usr/sbin/nologin --home-dir "$INSTALL_DIR" "$SERVICE_USER"
  ok "User '$SERVICE_USER' created"
else
  ok "User '$SERVICE_USER' already exists"
fi

# ─── Check that build artifacts exist ────────────────────────────────────
info "Checking build artifacts"
BACKEND_BIN="$ROOT_DIR/backend/build/endoriumfort_backend"
FRONTEND_DIST="$ROOT_DIR/frontend/dist"

if [[ ! -f "$BACKEND_BIN" ]]; then
  fail "Backend binary not found at $BACKEND_BIN — run build-all.sh first"
fi
if [[ ! -d "$FRONTEND_DIST" ]]; then
  fail "Frontend dist not found at $FRONTEND_DIST — run build-all.sh first"
fi
ok "Build artifacts found"

# ─── Deploy files ────────────────────────────────────────────────────────
info "Deploying to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"/{bin,frontend,data,recordings,logs}

# Backend binary
cp "$BACKEND_BIN" "$INSTALL_DIR/bin/endoriumfort_backend"
chmod 755 "$INSTALL_DIR/bin/endoriumfort_backend"

# Frontend static files
rsync -a --delete "$FRONTEND_DIST/" "$INSTALL_DIR/frontend/"

# Set ownership
chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
ok "Files deployed"

# ─── systemd service ────────────────────────────────────────────────────
info "Installing systemd service"
cat > /etc/systemd/system/endoriumfort.service <<EOF
[Unit]
Description=EndoriumFort PAM Backend
Documentation=https://github.com/NergYR/EndoriumFort
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR/data
ExecStart=$INSTALL_DIR/bin/endoriumfort_backend
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$INSTALL_DIR/data $INSTALL_DIR/recordings $INSTALL_DIR/logs

# Environment
Environment=HOME=$INSTALL_DIR

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=endoriumfort

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable endoriumfort
ok "systemd service installed & enabled"

# ─── Nginx configuration ────────────────────────────────────────────────
info "Configuring Nginx"

SERVER_NAME="${DOMAIN:-_}"
NGINX_CONF="/etc/nginx/sites-available/endoriumfort"
NGINX_ENABLED="/etc/nginx/sites-enabled/endoriumfort"

# Some distros use conf.d instead of sites-available
if [[ ! -d "/etc/nginx/sites-available" ]]; then
  mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
  # Add include if not present
  if ! grep -q "sites-enabled" /etc/nginx/nginx.conf; then
    sed -i '/http {/a\    include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
  fi
fi

cat > "$NGINX_CONF" <<'NGINX'
# ─── EndoriumFort — Nginx reverse proxy ──────────────────────────────────
# Auto-generated by deploy-prod.sh

upstream endoriumfort_backend {
    server 127.0.0.1:__BACKEND_PORT__;
    keepalive 32;
}

server {
    listen 80;
    server_name __SERVER_NAME__;

    # Frontend static files
    root __INSTALL_DIR__/frontend;
    index index.html;

    # Security headers (complement backend middleware)
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Gzip
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml image/svg+xml;
    gzip_min_length 256;

    # API & proxy — forward to backend
    location /api/ {
        proxy_pass http://endoriumfort_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # WebSocket endpoints
    location /ws/ {
        proxy_pass http://endoriumfort_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }

    # Web proxy passthrough
    location /proxy/ {
        proxy_pass http://endoriumfort_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_buffering off;
    }

    # SPA fallback — all other routes serve index.html
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets aggressively
    location /assets/ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Deny dotfiles
    location ~ /\. {
        deny all;
        return 404;
    }
}
NGINX

# Substitute placeholders
sed -i "s|__BACKEND_PORT__|$BACKEND_PORT|g" "$NGINX_CONF"
sed -i "s|__SERVER_NAME__|$SERVER_NAME|g" "$NGINX_CONF"
sed -i "s|__INSTALL_DIR__|$INSTALL_DIR|g" "$NGINX_CONF"

# Enable site
ln -sf "$NGINX_CONF" "$NGINX_ENABLED"

# Remove default site if it exists
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

# Test and reload
nginx -t || fail "Nginx configuration test failed"
ok "Nginx configured"

# ─── TLS Setup ───────────────────────────────────────────────────────────
case "$TLS" in
  letsencrypt)
    if [[ -z "$DOMAIN" ]]; then
      warn "No --domain specified, skipping Let's Encrypt. Use --self-signed or provide a domain."
    else
      info "Setting up Let's Encrypt TLS for $DOMAIN"
      certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email || {
        warn "Certbot failed. You can run it manually: sudo certbot --nginx -d $DOMAIN"
      }
      ok "TLS configured via Let's Encrypt"
    fi
    ;;
  self-signed)
    info "Generating self-signed certificate"
    CERT_DIR="/etc/ssl/endoriumfort"
    mkdir -p "$CERT_DIR"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "$CERT_DIR/key.pem" \
      -out "$CERT_DIR/cert.pem" \
      -subj "/CN=${DOMAIN:-endoriumfort}/O=EndoriumFort/C=FR" 2>/dev/null

    # Inject SSL into Nginx config
    sed -i "s/listen 80;/listen 80;\n    listen 443 ssl;\n    ssl_certificate $CERT_DIR\/cert.pem;\n    ssl_certificate_key $CERT_DIR\/key.pem;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ciphers HIGH:!aNULL:!MD5;/" "$NGINX_CONF"
    nginx -t || fail "Nginx TLS configuration test failed"
    ok "Self-signed TLS configured ($CERT_DIR)"
    warn "Self-signed certificates will show browser warnings"
    ;;
  none)
    warn "TLS disabled — traffic will be unencrypted (HTTP only)"
    ;;
esac

# ─── Start services ─────────────────────────────────────────────────────
info "Starting services"
systemctl restart endoriumfort
systemctl restart nginx

# Wait a moment and check health
sleep 2
if curl -sf "http://127.0.0.1:$BACKEND_PORT/api/health" >/dev/null 2>&1; then
  ok "Backend is healthy"
else
  warn "Backend health check failed — check: journalctl -u endoriumfort -f"
fi

# ─── Summary ─────────────────────────────────────────────────────────────
info "Deployment complete!"
echo
echo "  Install dir:  $INSTALL_DIR"
echo "  Backend:      127.0.0.1:$BACKEND_PORT (internal)"
echo "  Frontend:     Nginx → $INSTALL_DIR/frontend/"
echo "  Service:      systemctl {start|stop|restart|status} endoriumfort"
echo "  Logs:         journalctl -u endoriumfort -f"
echo "  Nginx logs:   /var/log/nginx/access.log"
echo

if [[ -n "$DOMAIN" ]]; then
  PROTO="http"
  [[ "$TLS" != "none" ]] && PROTO="https"
  echo "  URL: ${PROTO}://${DOMAIN}"
else
  echo "  URL: http://<server-ip>"
fi

echo
echo "  Default login:  admin / Admin123"
echo "  ⚠ CHANGE THE ADMIN PASSWORD IMMEDIATELY!"
echo
echo "  Useful commands:"
echo "    sudo systemctl status endoriumfort    # Check backend status"
echo "    sudo journalctl -u endoriumfort -f    # Stream backend logs"
echo "    sudo nginx -t && sudo systemctl reload nginx  # Reload Nginx"
echo
