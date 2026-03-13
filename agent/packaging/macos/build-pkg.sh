#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RELEASE_DIR="${RELEASE_DIR:-$ROOT_DIR/release}"
OUT_DIR="${OUT_DIR:-$RELEASE_DIR/packages/macos}"
VERSION="${VERSION:-}"
BINARY="${BINARY:-}"
ARCH="${ARCH:-}"

if [[ -z "$VERSION" ]]; then
  if [[ -f "$ROOT_DIR/agent/VERSION" ]]; then
    VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/agent/VERSION")"
  else
    echo "VERSION is required (env VERSION=1.2.3)" >&2
    exit 1
  fi
fi

if [[ -z "$BINARY" ]]; then
  echo "BINARY is required (path to darwin agent binary)" >&2
  exit 1
fi

if [[ ! -x "$BINARY" ]]; then
  echo "BINARY is not executable: $BINARY" >&2
  exit 1
fi

if [[ -z "$ARCH" ]]; then
  ARCH="$(basename "$BINARY" | sed -E 's/^.*darwin-//')"
  [[ -z "$ARCH" ]] && ARCH="universal"
fi

if ! command -v pkgbuild >/dev/null 2>&1; then
  echo "pkgbuild is required (run on macOS with Xcode command line tools)." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PAYLOAD_ROOT="$WORK_DIR/payload"
APP_DIR="$PAYLOAD_ROOT/Applications/EndoriumFortAgent.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"

mkdir -p "$MACOS_DIR"
cp "$BINARY" "$MACOS_DIR/endoriumfort-agent-bin"
chmod +x "$MACOS_DIR/endoriumfort-agent-bin"

cat > "$MACOS_DIR/endoriumfort-agent-launcher" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$DIR/endoriumfort-agent-bin" open-link "$1"
EOF
chmod +x "$MACOS_DIR/endoriumfort-agent-launcher"

cat > "$CONTENTS_DIR/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>EndoriumFortAgent</string>
  <key>CFBundleDisplayName</key>
  <string>EndoriumFort Agent</string>
  <key>CFBundleIdentifier</key>
  <string>space.endorium.agent</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleExecutable</key>
  <string>endoriumfort-agent-launcher</string>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLName</key>
      <string>EndoriumFort Link</string>
      <key>CFBundleURLSchemes</key>
      <array>
        <string>endoriumfort</string>
      </array>
    </dict>
  </array>
</dict>
</plist>
EOF

PKG_OUT="$OUT_DIR/EndoriumFortAgent-${VERSION}-darwin-${ARCH}.pkg"
pkgbuild \
  --root "$PAYLOAD_ROOT" \
  --identifier "space.endorium.agent" \
  --version "$VERSION" \
  --install-location "/" \
  "$PKG_OUT"

echo "macOS package created: $PKG_OUT"