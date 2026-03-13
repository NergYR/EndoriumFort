#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.prod.yml"
ENV_FILE="$ROOT_DIR/.env.prod"

usage() {
  cat <<'EOF'
Usage: ./run-prod.sh <command>

Commands:
  start      Start production stack
  stop       Stop production stack
  restart    Restart production stack
  logs       Follow logs
  status     Show services status
  pull       Pull latest image for configured tag
  update     Pull then recreate services
  config     Validate/render compose config
EOF
}

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
    return
  fi

  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
    return
  fi

  echo "[run-prod] ERROR: Docker Compose is not available (docker compose / docker-compose)." >&2
  exit 1
}

ensure_files() {
  if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo "[run-prod] ERROR: Missing $COMPOSE_FILE" >&2
    exit 1
  fi

  if [[ ! -f "$ENV_FILE" ]]; then
    if [[ -f "$ROOT_DIR/.env.prod.example" ]]; then
      cp "$ROOT_DIR/.env.prod.example" "$ENV_FILE"
      echo "[run-prod] Created $ENV_FILE from .env.prod.example"
      echo "[run-prod] Edit $ENV_FILE before launching in production."
    else
      echo "[run-prod] ERROR: Missing $ENV_FILE and no .env.prod.example found." >&2
      exit 1
    fi
  fi
}

main() {
  local command="${1:-}"

  if [[ -z "$command" ]]; then
    usage
    exit 1
  fi

  ensure_files

  case "$command" in
    start)
      compose up -d
      ;;
    stop)
      compose down
      ;;
    restart)
      compose down
      compose up -d
      ;;
    logs)
      compose logs -f --tail=200
      ;;
    status)
      compose ps
      ;;
    pull)
      compose pull
      ;;
    update)
      compose pull
      compose up -d --remove-orphans
      ;;
    config)
      compose config
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      echo "[run-prod] Unknown command: $command" >&2
      usage
      exit 1
      ;;
  esac
}

main "$@"
