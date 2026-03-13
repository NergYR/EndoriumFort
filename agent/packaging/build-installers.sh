#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${VERSION:-$(tr -d '[:space:]' < "$ROOT_DIR/agent/VERSION" 2>/dev/null || echo "0.0.0") }"
VERSION="$(echo "$VERSION" | tr -d '[:space:]')"

case "$(uname -s | tr '[:upper:]' '[:lower:]')" in
  linux)
    VERSION="$VERSION" bash "$ROOT_DIR/agent/packaging/linux/build-packages.sh"
    ;;
  darwin)
    echo "Run macOS packaging with explicit binary target, e.g.:"
    echo "  VERSION=$VERSION BINARY=$ROOT_DIR/release/endoriumfort-agent-darwin-arm64 ARCH=arm64 bash $ROOT_DIR/agent/packaging/macos/build-pkg.sh"
    ;;
  *)
    echo "Unsupported OS for this helper. Use platform-specific packaging scripts." >&2
    exit 1
    ;;
esac
