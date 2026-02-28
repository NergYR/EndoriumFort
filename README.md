# EndoriumFort

EndoriumFort is a PAM (Privileged Access Management) bastion system inspired by Wallix, Systancia Gate/Cleanroom, Teleport, and Apache Guacamole. It focuses on a clean, auditable access path from users to LAN targets with a gateway and WebBastion control plane.

## Architecture
```
Browser ←→ 127.0.0.1:local_port ←→ EndoriumFortAgent ←→ WebSocket ←→ Backend ←→ Target Resource
```

### Agent-Based Tunnel (v0.0.111) ✨ NEW
EndoriumFort uses a **Systancia-style local agent** for transparent access to web resources:

1. **EndoriumFortAgent** runs on the user's workstation
2. Agent authenticates with the bastion backend
3. Agent opens a local TCP listener (`127.0.0.1:<port>`)
4. Browser connects to `http://127.0.0.1:<port>` — the app works as if accessed directly
5. All traffic is tunneled through WebSocket to the backend, then forwarded to the target

**Benefits over reverse proxy:**
- No URL rewriting, no cookie path issues, no AJAX compatibility problems
- Target app sees native requests — 100% transparent
- Works with any web app (phpMyAdmin, OpenWRT, etc.) without modification
- Full audit trail of tunnel connections

## How it works

### Core Features (v0.2.0)

1. **User Authentication & Security**
   - Token-based auth system with Bearer tokens and **1-hour expiration** ✨ v0.2.0
   - **Password hashing** — SHA-256 with random salt, 10000 iterations ✨ v0.2.0
   - **Password policy** — min 8 chars, upper + lower + digit required ✨ v0.2.0
   - **Server-side logout** — tokens properly invalidated ✨ v0.2.0
   - Role-based access control (admin, operator, auditor)
   - **Two-Factor Authentication (TOTP/2FA)** — Compatible with Google Authenticator ✨ v0.1.0
   - **Login audit trail** — all login/logout/failure events recorded ✨ v0.2.0
   - Default credentials: admin/Admin123 (auto-hashed on first login)

2. **Resource Management**
   - SSH sessions with live WebSocket console (libssh2)
   - **HTTP/HTTPS web resources with transparent proxy**
   - **RDP support framework** (requires FreeRDP) ✨ v0.1.0
   - Role-based permission grants per user
   - Support for multiple protocols on a single dashboard

3. **Session Management**
   - Start, terminate, and monitor live sessions
   - SSH console with real-time terminal emulation (xterm.js)
   - **Automatic SSH session recording** in Asciinema format ✨ v0.1.0
   - Session history and filtering

4. **Session Recording & Replay** ✨ v0.1.0
   - All SSH sessions automatically recorded in Asciinema v2 (.cast) format
   - Input/output timestamped for complete audit trail
   - Download `.cast` files for replay with `asciinema play`
   - Text-based replay viewer in the browser
   - Filterable by session ID

5. **Two-Factor Authentication (2FA)** ✨ v0.1.0
   - RFC 6238 TOTP with built-in crypto (no external dependency)
   - QR code generation for easy authenticator app setup
   - Enable/disable with code verification
   - Login flow: password → TOTP code → access granted

6. **Self-Service Account Management** ✨ v0.2.0
   - **Change password** modal with current password verification
   - Password policy validation with clear error messages
   - Audit trail for password changes

7. **Dark Mode** ✨ v0.2.0
   - Toggle via 🌙/☀️ button on all pages
   - Persisted in localStorage
   - Complete dark theme across all components

8. **Web Proxy** ✨ v0.0.14
   - Transparent HTTP reverse proxy for web resources
   - All traffic tunneled through bastion
   - Same iframe-based access for seamless UX
   - Full audit trail of proxy access

9. **Audit & Compliance**
   - All events logged to `audit-log.jsonl` (JSONL format)
   - User actions: login, logout, session create/terminate, proxy access
   - Login success/failure tracking with IP and username ✨ v0.2.0
   - Audit viewer in admin panel with role-based filtering

10. **Admin Console**
   - User account management (create/edit/delete)
   - Resource administration (create/edit/delete)
   - Permission grants (user → resource mappings)
   - Audit log viewer with filtering

All session data is stored in-memory with SQLite database backend. Audit events are appended to a local JSONL file. The implementation establishes complete flow from authentication through session management to audit compliance.

## Structure
- **frontend**: Vite + React UI (WebBastion dashboard)
- **backend**: C++ Crow API (auth, resources, audit, WebSocket tunnel)
- **agent**: Go CLI agent (EndoriumFortAgent — local tunnel client)

## Quick Start — Agent Tunnel

### 1. Build everything
```bash
./build-all.sh
```

### 2. Start the backend
```bash
cd backend/build && ./endoriumfort_backend
```

### 3. Use the agent
```bash
# Login and get a token
./agent/endoriumfort-agent login --server http://bastion:8080 --user admin --password admin

# List available resources
./agent/endoriumfort-agent list --server http://bastion:8080 --token tok-1000

# Open a tunnel to resource #3 on local port 8888
./agent/endoriumfort-agent connect --server http://bastion:8080 --token tok-1000 --resource 3 --local-port 8888

# Now open http://127.0.0.1:8888 in your browser!
```

## UI highlights (major update)
The WebBastion UI is streamlined to the essentials for daily operations:

- Dedicated login screen before entering the console.
- Resource tiles (Systancia-style) to launch sessions from admin-managed assets.
- Separate admin console for creating and maintaining resources.
- Admin-managed user accounts with default admin/admin login.
- Minimal session management for start, terminate, and live SSH supervision.
- Focused console layout with health status and auth guardrails.
- Endorium palette aligned with the product logo.

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

### Web Proxy Features (v0.0.56)

The HTTP/HTTPS proxy now uses **cookie-based authentication** for transparent access to web resources:

#### Cookie-Based Authentication
- Tokens stored in `endoriumfort_token` cookie (automatic, transparent to users)
- Cookie path set per-resource (`/proxy/{resourceId}/`) for security isolation
- Cookie is emitted as `HttpOnly; SameSite=Lax` for local HTTP development (`localhost`)
- Token extraction fallback: Authorization Bearer → query param → Cookie header
- `Set-Cookie` header automatically sent in responses

#### HTML Path Rewriting
- Absolute paths (`href="/path"`, `src="/path"`) automatically converted to proxified paths (`/proxy/{resourceId}/path`)
- Base tag injection enables proper relative URL resolution
- Handles all URL token types: `href="/`, `src="/`, `action="/`, `url(/`
- Skips already-proxified URLs and external absolute links

#### User Experience
- **iframe-based access** in frontend - resources display inline with authentication transparent
- **"↗ Nouvel onglet" button** - Opens resource in new tab, preserving cookie-based auth
- **No credential injection** - All auth handled via cookies, no tokens in URLs
- **Seamless redirects** - Location headers properly rewritten and tokens preserved

#### Setup Example
1. Create a web resource pointing to target (e.g., `192.168.0.31` for OpenWRT LuCI)
2. Ensure `protocol: "http"` or `"https"`
3. Access via `http://localhost:8080/proxy/{resourceId}/path`
4. Authentication handled automatically via cookies + header injection

## One-command build and launch
Use the root script to compile and launch the stack:

- **Linux/Mac:** `./run-dev.sh` (new dev script that starts both backend+frontend)
- **PowerShell:** `./build-all.ps1`

The dev script will:
1. Rebuild backend (make -j$(nproc))
2. Start backend on port 8080
3. Start frontend dev server on port 5173 (auto-reload)
4. Display logs: `tail -f /tmp/backend.log` and `tail -f /tmp/frontend.log`

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

### TCP Tunnel (NEW v0.0.111) — EndoriumFortAgent
- WebSocket: `/ws/tunnel?token=...&resource_id=...`
  - Binary WebSocket messages forwarded bidirectionally to target TCP
  - Authentication via `token` query param (Bearer token)
  - Resource authorization checked (admin or permission grant)
  - Audit events: `tunnel.open`, `tunnel.close`
  - One WebSocket per local TCP connection (multiplexed by agent)

**Protocol flow:**
1. Agent opens WebSocket: `ws://backend:8080/ws/tunnel?token=tok-1000&resource_id=3`
2. Backend authenticates, connects TCP to target resource (e.g., 192.168.0.16:8080)
3. All binary WebSocket messages are forwarded as raw TCP data
4. Connection closes when either side disconnects

### Web Proxy (NEW v0.0.14)
- GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS /proxy/{resourceId}/*
  - Transparent HTTP reverse proxy for web resources
  - All requests/responses tunnel through bastion
  - Auth token required (Bearer)
  - Requires user permission grant on resource
  
**Example:**
```bash
curl -H "Authorization: Bearer tok-1000" \
  http://localhost:8080/proxy/1/path/to/resource?param=value
```

### Resources (NEW)
- GET /api/resources
  - Filter by user permissions (admin sees all, others see only permitted)
- POST /api/resources (admin only)
  - Body: `{ "name": "...", "target": "...", "protocol": "ssh|http|https", "port": 22 }`
- PUT /api/resources/:id (admin only)
- DELETE /api/resources/:id (admin only)
- GET /api/users/{userId}/resources
  - Get permissions for a user
- POST /api/users/{userId}/resources/{resourceId}
  - Grant user access to resource
- DELETE /api/users/{userId}/resources/{resourceId}
  - Revoke user access from resource

### Web Proxy Viewer (NEW)
- GET /webproxy
  - React component that displays web resources in responsive iframe
  - Accessed via dashboard "Connect" button on HTTP/HTTPS resources
  - Transparent to user - they see the content as if direct

### Two-Factor Authentication (NEW v0.1.0)
- POST /api/auth/setup-2fa — Generate TOTP secret + QR code URI
- POST /api/auth/verify-2fa — Verify and enable 2FA `{ "code": "123456" }`
- POST /api/auth/disable-2fa — Disable 2FA `{ "code": "123456" }`
- GET /api/auth/2fa-status — Check if 2FA is enabled for current user
- Login with 2FA: POST /api/auth/login `{ "username":"…", "password":"…", "totpCode":"123456" }`
  - Returns `{"status":"2fa_required"}` if code missing and 2FA enabled

### Auth (NEW v0.2.0)
- POST /api/auth/login — Returns token with `expiresAt` field (1h TTL)
  - Body: `{ "user": "admin", "password": "Admin123" }`
  - Returns: `{ "token": "eft_...", "user": "admin", "role": "admin", "expiresAt": "..." }`
  - Passwords verified via SHA-256 hash (legacy plaintext auto-migrated)
- POST /api/auth/logout — Invalidate token server-side
- POST /api/auth/change-password — Change current user's password
  - Body: `{ "currentPassword": "...", "newPassword": "..." }`
  - Validates password policy (8+ chars, upper + lower + digit)

### Session Recordings (NEW v0.1.0)
- GET /api/recordings — List all recordings (optional `?sessionId=` filter)
- GET /api/recordings/:id — Get recording metadata (JSON)
- GET /api/recordings/:id/cast — Download `.cast` file (Asciinema v2 format)
  - Replay with: `asciinema play recording.cast`

### RDP WebSocket (NEW v0.1.0)
- WebSocket: `/api/ws/rdp` — RDP session proxy (requires FreeRDP at compile time)
  - Returns 501 if compiled without FreeRDP support

### Audit
- GET /api/audit — Audit events now include login/logout/failure tracking
- POST /api/audit

### Auth (legacy)
- POST /api/auth/login
  - Body: `{ "user": "admin", "password": "admin" }`
  - Returns: `{ "token": "tok-1000", "user": "admin", "role": "admin" }`

### Users
- GET /api/users (admin only)
- POST /api/users (admin only)
- PUT /api/users/:id (admin only)
- DELETE /api/users/:id (admin only)

### Web Proxy (NEW v0.0.14)
- GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS /proxy/{resourceId}/*
  - Transparent HTTP reverse proxy for web resources
  - All requests/responses tunnel through bastion
  - Auth token required (Bearer)
  - Returns proxied response with original headers
  - Requires user permission grant on resource
  
**Example:**
```bash
curl -H "Authorization: Bearer tok-1000" \
  http://localhost:8080/proxy/1/path/to/resource?param=value
```

### Resources (NEW)
- GET /api/resources
  - Filter by user permissions (admin sees all, others see only permitted)
- POST /api/resources (admin only)
  - Body: `{ "name": "...", "target": "...", "protocol": "ssh|http|https", "port": 22 }`
- PUT /api/resources/:id (admin only)
- DELETE /api/resources/:id (admin only)
- GET /api/users/{userId}/resources
  - Get permissions for a user
- POST /api/users/{userId}/resources/{resourceId}
  - Grant user access to resource
- DELETE /api/users/{userId}/resources/{resourceId}
  - Revoke user access from resource

### Web Proxy Viewer (NEW)
- GET /webproxy
  - React component that displays web resources in iframe
  - Accessed via dashboard "Connect" button on HTTP/HTTPS resources
  - Transparent to user
- `id` (integer)
- `target` (string)
- `user` (string)
- `protocol` (string)
- `status` (active or terminated)
- `createdAt` (UTC ISO string)
- `terminatedAt` (UTC ISO string, optional)

## Development flow
1. Start backend and frontend with: `./run-dev.sh`
2. Open browser to http://localhost:5173
3. Login with admin/admin
4. Create resources (SSH or HTTP) from admin panel
5. Assign permissions to users
6. Test sessions from dashboard

## Notes
- Session storage is in-memory and resets on restart.
- Audit log is appended to `audit-log.jsonl` in the backend working directory.
- Audit payloads are stored as raw JSON objects.
- Auth is token-based with operator, admin, and auditor roles.
- **Web proxy requires active token and user permission on resource.**
- Default database: `endoriumfort.db` (SQLite3)
- Version auto-incremented on each build (currently v0.0.14)

## Features Documentation
- See [PROXY_IMPLEMENTATION.md](PROXY_IMPLEMENTATION.md) for detailed proxy documentation
- See [FEATURES.md](FEATURES.md) for complete feature list
- See [CHANGELOG.md](CHANGELOG.md) for version history
