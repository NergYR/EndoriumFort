#!/usr/bin/env bash
set -euo pipefail

DESKTOP_FILE="$HOME/.local/share/applications/endoriumfort-agent.desktop"
rm -f "$DESKTOP_FILE"

echo "Protocol endoriumfort:// supprimé (desktop local retiré)."
