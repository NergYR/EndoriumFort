# EndoriumFort

EndoriumFort is a minimal monorepo scaffold for an agentless bastion system inspired by Wallix, Systancia Gate/Cleanroom, Teleport, and Apache Guacamole. It focuses on a clean, auditable access path from users to LAN targets with a gateway and WebBastion control plane.

## Architecture
LAN <=> GW (EndoriumFortGW) <=> EndoriumFort (WebBastion) <=> Users

## How it works
The current implementation models the control plane only:

1. Users authenticate into the WebBastion UI.
2. The UI requests a session through the API.
3. The gateway is represented by a placeholder session broker that tracks status.
4. Audit events are accepted and stored locally in a JSONL file.

All session data is stored in-memory for now. Audit events are also cached in-memory and appended to a local JSONL file. The goal is to establish the flow and data model before wiring real session brokering, protocol translation, and persistent storage.

## Structure
- frontend: Vite + React UI
- backend: C++ Crow API

## UI highlights (major update)
The WebBastion UI now mirrors production bastion consoles with a unified dashboard:

- Centralized dashboard with KPIs, health, and alerts.
- Session management for start, terminate, and live supervision.
- Access control panel with role-based summaries.
- Recording and audit timeline for traceability.
- Notifications and alert feed for risk events.
- Authentication and integration touchpoints (SAML/OIDC, LDAP, SIEM).
- Personalization tiles and protocol hub (SSH, RDP, VNC, HTTP).

See [CHANGELOG.md](CHANGELOG.md) for the UI update entry.

## Frontend (Vite + React)
- Dev server: `npm install` then `npm run dev` in frontend
- Build: `npm run build`
  - Dev proxy: `/api` -> `http://localhost:8080`

## Backend (C++ Crow)
- Build:
  - Configure: `cmake -S . -B build`
  - Compile: `cmake --build build`
- MinGW make (PowerShell): `./backend/build-mingw.ps1`
- Run: `./build/endoriumfort_backend`
- SQLite3 is required (headers + library). The backend stores sessions in `endoriumfort.db`.
- libssh2 is required on Linux for the Web SSH console (Live SSH console panel).

## One-command build and launch
Use the root script to compile and launch the stack:

- PowerShell: `./build-all.ps1`

## API
### Health
- GET /api/health

### Sessions
- GET /api/sessions
- Query params: `status`, `user`, `target`, `protocol`, `limit`, `offset`, `sort`
- POST /api/sessions
  - Body: `{ "target": "10.0.0.12", "user": "ops-admin", "protocol": "ssh", "port": 22 }`
- GET /api/sessions/:id
- POST /api/sessions/:id/terminate
- GET /api/sessions/stream (SSE-style event feed, supports `Last-Event-ID` or `?since=`)

### Web SSH console
- Available on Linux builds with libssh2.
- WebSocket: `/api/ws/ssh?token=...`
- Client sends JSON control messages:
  - `{"type":"start","sessionId":1,"password":"...","cols":120,"rows":32}`
  - `{"type":"input","data":"ls -la\n"}`
  - `{"type":"resize","cols":120,"rows":32}`

### Audit
- GET /api/audit
- POST /api/audit

### Auth
- POST /api/auth/login
  - Body: `{ "user": "ops-admin", "role": "operator" }`
  - Returns: `{ "token": "tok-1000", "user": "ops-admin", "role": "operator" }`

## Session model
Each session has:
- `id` (integer)
- `target` (string)
- `user` (string)
- `protocol` (string)
- `status` (active or terminated)
- `createdAt` (UTC ISO string)
- `terminatedAt` (UTC ISO string, optional)

## Development flow
1. Start backend on port 8080.
2. Start frontend on port 5173 (proxy forwards `/api`).
3. Create sessions from the UI and terminate them to validate the flow.

## Notes
- Session storage is in-memory and resets on restart.
- Audit log is appended to `audit-log.jsonl` in the backend working directory.
- Audit payloads are stored as raw JSON strings (or raw text if invalid JSON).
- Auth is a placeholder token flow with operator, admin, and auditor roles.
