#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

AGENT_BIN="${1:-$ROOT_DIR/endoriumfort-agent}"
if [[ ! -x "$AGENT_BIN" ]]; then
  echo "Agent introuvable ou non exécutable: $AGENT_BIN" >&2
  exit 1
fi

mkdir -p "$HOME/.local/share/applications"
DESKTOP_FILE="$HOME/.local/share/applications/endoriumfort-agent.desktop"

cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=EndoriumFort Agent
Comment=EndoriumFort deep-link handler
Exec=$AGENT_BIN open-link %u
NoDisplay=true
Terminal=false
MimeType=x-scheme-handler/endoriumfort;
Categories=Network;
EOF

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$HOME/.local/share/applications" >/dev/null 2>&1 || true
fi

if command -v xdg-mime >/dev/null 2>&1; then
  xdg-mime default endoriumfort-agent.desktop x-scheme-handler/endoriumfort || true
fi

echo "Protocol endoriumfort:// installé (utilisateur courant)."
echo "Desktop file: $DESKTOP_FILE"