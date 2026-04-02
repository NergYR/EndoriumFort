#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RELEASE_DIR="${RELEASE_DIR:-$ROOT_DIR/release}"
OUT_DIR="${OUT_DIR:-$RELEASE_DIR/packages/linux}"
VERSION="${VERSION:-}"

if [[ -z "$VERSION" ]]; then
  if [[ -f "$ROOT_DIR/agent/VERSION" ]]; then
    VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/agent/VERSION")"
  else
    echo "VERSION is required (env VERSION=1.2.3)" >&2
    exit 1
  fi
fi

if ! command -v fpm >/dev/null 2>&1; then
  echo "fpm is required (gem install --no-document fpm)" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

build_relay_deb() {
  local relay_bin="$RELEASE_DIR/endoriumfort-relay-linux-amd64"
  if [[ ! -f "$relay_bin" ]]; then
    echo "Missing relay binary: $relay_bin" >&2
    exit 1
  fi

  local payload_root="$WORK_DIR/relay-payload"
  mkdir -p "$payload_root/usr/local/bin"

  install -m 0755 "$relay_bin" "$payload_root/usr/local/bin/endoriumfort-relay"

  fpm -s dir -t deb \
    -n endoriumfort-relay \
    -v "$VERSION" \
    --architecture amd64 \
    --description "EndoriumFort Relay daemon for distributed bastion control plane" \
    --url "https://github.com/NergYR/EndoriumFort" \
    --license "MIT" \
    --maintainer "EndoriumFort" \
    -C "$payload_root" \
    --package "$OUT_DIR/endoriumfort-relay_${VERSION}_amd64.deb" \
    .
}

build_web_bastion_deb() {
  local payload_root="$WORK_DIR/web-bastion-payload"
  local postinst="$WORK_DIR/web-bastion-postinst.sh"

  mkdir -p "$payload_root/opt/endoriumfort"
  mkdir -p "$payload_root/usr/local/bin"
  mkdir -p "$payload_root/etc/endoriumfort"

  install -m 0644 "$ROOT_DIR/docker-compose.prod.yml" "$payload_root/opt/endoriumfort/docker-compose.prod.yml"
  install -m 0644 "$ROOT_DIR/.env.prod.example" "$payload_root/etc/endoriumfort/.env.prod.example"
  install -m 0755 "$ROOT_DIR/run-prod.sh" "$payload_root/opt/endoriumfort/run-prod.sh"

  cat > "$payload_root/usr/local/bin/endoriumfort-web-bastion" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/endoriumfort/.env.prod"
COMPOSE_FILE="/opt/endoriumfort/docker-compose.prod.yml"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE. Copy /etc/endoriumfort/.env.prod.example and adjust values." >&2
  exit 1
fi

exec docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
EOF
  chmod 0755 "$payload_root/usr/local/bin/endoriumfort-web-bastion"

  cat > "$postinst" <<'EOF'
#!/usr/bin/env bash
set -e
mkdir -p /etc/endoriumfort
if [[ ! -f /etc/endoriumfort/.env.prod ]]; then
  cp /etc/endoriumfort/.env.prod.example /etc/endoriumfort/.env.prod
fi
EOF
  chmod +x "$postinst"

  fpm -s dir -t deb \
    -n endoriumfort-web-bastion \
    -v "$VERSION" \
    --architecture all \
    --description "EndoriumFort Web Bastion deployment bundle (Docker Compose + helper CLI)" \
    --url "https://github.com/NergYR/EndoriumFort" \
    --license "MIT" \
    --maintainer "EndoriumFort" \
    --depends docker.io \
    --after-install "$postinst" \
    -C "$payload_root" \
    --package "$OUT_DIR/endoriumfort-web-bastion_${VERSION}_all.deb" \
    .
}

build_relay_deb
build_web_bastion_deb

echo "APT DEB packages created in: $OUT_DIR"
