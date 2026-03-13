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

create_payload() {
  local src_bin="$1"
  local payload_root="$2"
  mkdir -p "$payload_root/usr/local/bin"
  mkdir -p "$payload_root/usr/share/applications"
  mkdir -p "$payload_root/opt/endoriumfort-agent/installers/linux"

  install -m 0755 "$src_bin" "$payload_root/usr/local/bin/endoriumfort-agent"
  install -m 0755 "$ROOT_DIR/agent/installers/linux/install-protocol.sh" "$payload_root/opt/endoriumfort-agent/installers/linux/install-protocol.sh"
  install -m 0755 "$ROOT_DIR/agent/installers/linux/uninstall-protocol.sh" "$payload_root/opt/endoriumfort-agent/installers/linux/uninstall-protocol.sh"

  cat > "$payload_root/usr/share/applications/endoriumfort-agent.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=EndoriumFort Agent
Comment=EndoriumFort deep-link handler
Exec=/usr/local/bin/endoriumfort-agent open-link %u
NoDisplay=true
Terminal=false
MimeType=x-scheme-handler/endoriumfort;
Categories=Network;
EOF
}

create_postinst() {
  local file="$1"
  cat > "$file" <<'EOF'
#!/usr/bin/env bash
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
fi
if command -v xdg-mime >/dev/null 2>&1; then
  xdg-mime default endoriumfort-agent.desktop x-scheme-handler/endoriumfort >/dev/null 2>&1 || true
fi
EOF
  chmod +x "$file"
}

build_for_arch() {
  local goarch="$1"
  local deb_arch="$2"
  local rpm_arch="$3"
  local input_bin="$RELEASE_DIR/endoriumfort-agent-linux-$goarch"

  if [[ ! -f "$input_bin" ]]; then
    echo "Missing binary: $input_bin" >&2
    exit 1
  fi

  local payload_root="$WORK_DIR/payload-$goarch"
  local postinst="$WORK_DIR/postinst-$goarch.sh"
  create_payload "$input_bin" "$payload_root"
  create_postinst "$postinst"

  fpm -s dir -t deb \
    -n endoriumfort-agent \
    -v "$VERSION" \
    --architecture "$deb_arch" \
    --description "EndoriumFort Agent deep-link client" \
    --url "https://github.com/NergYR/EndoriumFort" \
    --license "MIT" \
    --maintainer "EndoriumFort" \
    --after-install "$postinst" \
    -C "$payload_root" \
    --package "$OUT_DIR/endoriumfort-agent_${VERSION}_${deb_arch}.deb" \
    .

  fpm -s dir -t rpm \
    -n endoriumfort-agent \
    -v "$VERSION" \
    --architecture "$rpm_arch" \
    --description "EndoriumFort Agent deep-link client" \
    --url "https://github.com/NergYR/EndoriumFort" \
    --license "MIT" \
    --maintainer "EndoriumFort" \
    --after-install "$postinst" \
    -C "$payload_root" \
    --package "$OUT_DIR/endoriumfort-agent-${VERSION}-1.${rpm_arch}.rpm" \
    .
}

build_for_arch "amd64" "amd64" "x86_64"
build_for_arch "arm64" "arm64" "aarch64"

echo "Linux packages created in: $OUT_DIR"