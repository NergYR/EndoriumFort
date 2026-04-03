#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LAUNCHER_SOURCE="$ROOT_DIR/agent/packaging/macos/EndoriumFortAgentLauncher.swift"

AGENT_BIN="${1:-$ROOT_DIR/endoriumfort-agent-darwin-arm64}"
if [[ ! -x "$AGENT_BIN" ]]; then
  ALT="$ROOT_DIR/endoriumfort-agent"
  if [[ -x "$ALT" ]]; then
    AGENT_BIN="$ALT"
  else
    echo "Agent introuvable ou non exécutable: $AGENT_BIN" >&2
    exit 1
  fi
fi

APP_DIR="$HOME/Applications/EndoriumFortAgent.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"

mkdir -p "$MACOS_DIR"
cp "$AGENT_BIN" "$MACOS_DIR/endoriumfort-agent-bin"
chmod +x "$MACOS_DIR/endoriumfort-agent-bin"

if command -v swiftc >/dev/null 2>&1 && [[ -f "$LAUNCHER_SOURCE" ]]; then
  swiftc "$LAUNCHER_SOURCE" -o "$MACOS_DIR/EndoriumFortAgentLauncher"
  chmod +x "$MACOS_DIR/EndoriumFortAgentLauncher"
else
  cat > "$MACOS_DIR/EndoriumFortAgentLauncher" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ "${1:-}" == endoriumfort://* ]]; then
  exec "$DIR/endoriumfort-agent-bin" open-link "$1"
fi
if command -v osascript >/dev/null 2>&1; then
  osascript -e 'display dialog "EndoriumFort Agent est installe. Cette app sert de handler pour les liens endoriumfort://." buttons {"OK"} default button "OK"' >/dev/null 2>&1 || true
fi
exit 0
EOF
  chmod +x "$MACOS_DIR/EndoriumFortAgentLauncher"
fi

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
  <string>1.0</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleExecutable</key>
  <string>EndoriumFortAgentLauncher</string>
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

LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
if [[ -x "$LSREGISTER" ]]; then
  "$LSREGISTER" -f "$APP_DIR" >/dev/null 2>&1 || true
fi

echo "Protocol endoriumfort:// installé via app bundle: $APP_DIR"
echo "Si nécessaire: ouvre Finder > Applications puis lance EndoriumFortAgent une fois."
