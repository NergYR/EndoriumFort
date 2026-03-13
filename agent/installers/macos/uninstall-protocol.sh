#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$HOME/Applications/EndoriumFortAgent.app"
if [[ -d "$APP_DIR" ]]; then
  rm -rf "$APP_DIR"
  echo "App supprimée: $APP_DIR"
else
  echo "Aucune app locale trouvée: $APP_DIR"
fi

LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
if [[ -x "$LSREGISTER" ]]; then
  "$LSREGISTER" -kill -r -domain local -domain system -domain user >/dev/null 2>&1 || true
fi

echo "Désinstallation du protocole terminée."
