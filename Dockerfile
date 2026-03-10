# ─── EndoriumFort — Multi-stage Dockerfile ───────────────────────────────
# Produces a minimal image with:
#   - C++ backend (Crow) on port 8080
#   - React frontend served by Nginx on port 80 (reverse-proxies to backend)
#
# Build: docker build -t endoriumfort .
# Run:   docker compose up -d

# ═══════════════════════════════════════════════════════════════════════════
#  Stage 1 — Build backend (C++17)
# ═══════════════════════════════════════════════════════════════════════════
FROM debian:bookworm-slim AS backend-build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git ca-certificates \
    libsqlite3-dev libssh2-1-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy backend sources
COPY backend/CMakeLists.txt backend/VERSION backend/
COPY backend/src/ backend/src/
COPY backend/scripts/ backend/scripts/

# Generate version.h if missing
RUN if [ ! -f backend/src/version.h ]; then \
      VER=$(cat backend/VERSION 2>/dev/null || echo "0.0.0"); \
      printf '#pragma once\n#define APP_VERSION "%s"\n' "$VER" > backend/src/version.h; \
    fi

# Build
RUN cmake -S backend -B backend/build \
      -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF \
      -DCMAKE_CXX_FLAGS="-O2" \
  && cmake --build backend/build -j"$(nproc)"

# ═══════════════════════════════════════════════════════════════════════════
#  Stage 2 — Build frontend (React + Vite)
# ═══════════════════════════════════════════════════════════════════════════
FROM node:22-slim AS frontend-build

WORKDIR /build/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts

COPY frontend/ ./
RUN npm run build

# ═══════════════════════════════════════════════════════════════════════════
#  Stage 3 — Production image
# ═══════════════════════════════════════════════════════════════════════════
FROM debian:bookworm-slim AS production

RUN apt-get update && apt-get install -y --no-install-recommends \
  nginx libsqlite3-0 libssh2-1 ca-certificates curl openssl certbot \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --shell /usr/sbin/nologin --home-dir /app endoriumfort

WORKDIR /app

# Backend binary
COPY --from=backend-build /build/backend/build/endoriumfort_backend /app/bin/endoriumfort_backend
RUN chmod 755 /app/bin/endoriumfort_backend

# Frontend static files
COPY --from=frontend-build /build/frontend/dist /app/frontend

# Nginx config
COPY docker/nginx.conf /etc/nginx/sites-available/default

# Default TLS certificate (self-signed) generated at build time
RUN mkdir -p /etc/nginx/tls \
  && openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout /etc/nginx/tls/tls.key \
    -out /etc/nginx/tls/tls.crt \
    -days 3650 \
    -subj "/C=FR/ST=IDF/L=Paris/O=EndoriumFort/OU=Docker/CN=localhost" \
  && chmod 600 /etc/nginx/tls/tls.key \
  && chmod 644 /etc/nginx/tls/tls.crt

# Entrypoint
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod 755 /app/entrypoint.sh

# Create data directories
RUN mkdir -p /app/data /app/recordings /app/logs \
  /var/www/certbot \
  && chown -R endoriumfort:endoriumfort /app/data /app/recordings /app/logs

# Volumes for persistent data
VOLUME ["/app/data", "/app/recordings"]

# Backend on 8080 (internal), Nginx on 80
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://127.0.0.1:8080/api/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
