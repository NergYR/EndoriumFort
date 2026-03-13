<p align="center">
  <img src="https://img.shields.io/github/v/release/NergYR/EndoriumFort?style=flat-square" alt="Latest release">
  <img src="https://img.shields.io/badge/license-Source--Available-orange?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/backend-C%2B%2B%2017-00599C?style=flat-square&logo=cplusplus" alt="C++">
  <img src="https://img.shields.io/badge/frontend-React%2018-61DAFB?style=flat-square&logo=react" alt="React">
  <img src="https://img.shields.io/badge/agent-Go%201.25.8-00ADD8?style=flat-square&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square" alt="Platform">
  <a href="https://github.com/NergYR/EndoriumFort/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/NergYR/EndoriumFort/ci.yml?branch=master&label=CI&style=flat-square" alt="CI"></a>
  <a href="https://github.com/NergYR/EndoriumFort/actions/workflows/release-gate.yml"><img src="https://img.shields.io/github/actions/workflow/status/NergYR/EndoriumFort/release-gate.yml?branch=master&label=Release%20Gate&style=flat-square" alt="Release Gate"></a>
  <a href="https://github.com/NergYR/EndoriumFort/actions/workflows/codeql.yml"><img src="https://img.shields.io/github/actions/workflow/status/NergYR/EndoriumFort/codeql.yml?branch=master&label=CodeQL&style=flat-square" alt="CodeQL"></a>
</p>

# EndoriumFort

**EndoriumFort** is an open-source **Privileged Access Management (PAM)** bastion system designed to secure, monitor, and audit remote access to your infrastructure. Inspired by [Wallix](https://www.wallix.com/), [Systancia Gate](https://www.systancia.com/), [Teleport](https://goteleport.com/), and [Apache Guacamole](https://guacamole.apache.org/).

> **One gateway. Every protocol. Full audit trail.**

---

## Highlights

| Feature | Description |
|---------|-------------|
| **Credential Vault** | Store SSH credentials securely - auto-injected on connection |
| **Web SSH Terminal** | Full xterm.js terminal in the browser via WebSocket |
| **SSH Snippets Studio** | Prebuilt + custom reusable SSH command snippets with one-click inject/execute |
| **HTTP/HTTPS Proxy** | Transparent web proxy with cookie-based auth |
| **Agent Tunnel** | Systancia-style local agent for zero-rewrite TCP tunneling |
| **Session Shadowing** | Real-time read-only observation of active sessions |
| **Session Recording** | Asciinema v2 format with animated in-browser replay |
| **2FA / TOTP** | RFC 6238 two-factor authentication with QR setup |
| **Granular Access Control** | Fine-grained permissions per action with per-user allow/deny overrides (role defaults still available) |
| **Live Dashboard** | Real-time KPI stats, session monitoring, security alerts |
| **Access-First Workspace** | Open resources and operate sessions from one page without context switching |
| **Security Center** | Live anomaly hints (login failures, stale sessions, admin-change activity, MFA posture) |
| **Quick Refresh** | One-click synchronization of sessions, resources, KPIs, users, and audit feed |
| **Recent Sessions Queue** | Prioritized latest sessions with direct terminate/audit actions |
| **Critical Session Watchlist** | Pin sessions for dedicated status-change tracking during incidents |
| **Audit CSV Export** | Export current filtered audit timeline for compliance and investigation workflows |
| **Session SLO Insights** | Real-time completion rate, average duration, and stale-session signals for operations teams |
| **Relay Control Plane (v1)** | Secure relay enrollment, heartbeat health, per-resource relay assignment, and route resolution (relay/direct fallback) |
| **Access Justification Trail** | Admin-configurable per-resource reason popup + ticket ID attached to session creation audits |
| **Access Playbooks** | Per-resource saved justification/purpose templates to accelerate compliant access requests |
| **Dual Approval Workflow** | Per-resource 4-eyes control with operator request submission and admin approve/deny queue |
| **SSH Command Guard** | Optional server-side dangerous command blocking with dedicated audit events |
| **Adaptive Risk Policy** | Per-resource risk level + ticket requirements for high-risk access |
| **Risk Preview** | Real-time session risk scoring before opening access (factors + effective level) |
| **Session DNA** | Tamper-evident per-session audit chain with integrity verification endpoint/UI |
| **Purpose-Bound Access** | High/critical-risk sessions require explicit purpose and optional evidence |
| **Live Security Notifications** | In-app toast alerts with configurable strict/normal/permissive filtering, per-type throttling, and severity-aware display caps |
| **Incident Escalation Banner** | Automatic high-visibility escalation when repeated critical signals are detected in a short time window |
| **Incident Lifecycle Cases** | Open and close active incident coordination cases directly from the escalation banner |
| **Containment Mode** | Incident-time guardrail that forces explicit session justification before opening access |
| **Behavior Anomaly Signal** | Command-volume spike detection on session close (`behavior.anomaly.command_spike`) |
| **Dark Mode** | Full dark theme with localStorage persistence |

---

## Architecture

```
┌──────────┐     HTTPS/WSS      ┌──────────────┐     SSH/TCP/HTTP     ┌──────────┐
│  Browser  │◄──────────────────►│  EndoriumFort │◄────────────────────►│  Targets  │
│  (React)  │                    │   Backend     │                      │  (LAN)    │
└──────────┘                    └──────────────┘                      └──────────┘
      ▲                                ▲
      │                                │
      │  http://127.0.0.1:<port>       │  WebSocket Tunnel
      │                                │
┌──────────┐                           │
│  Agent    │◄─────────────────────────┘
│  (Go CLI) │
└──────────┘
```

EndoriumFort operates in two modes:

- **Web Mode** — Browser connects directly to the backend for SSH terminals, web proxy, and session management
- **Agent Mode** — A local Go agent creates TCP tunnels via WebSocket, providing transparent access to any web application without URL rewriting

---

## Project Structure

```
EndoriumFort/
├── backend/            # C++17 API server (Crow framework)
│   ├── src/            #   main.cc, routes, SSH, tunnel, proxy, RDP
│   ├── CMakeLists.txt  #   CMake build with FetchContent (Asio, Crow)
│   └── VERSION         #   Backend version (1.0.0)
├── frontend/           # React 18 + Vite 7 SPA
│   ├── src/            #   App.jsx, styles.css, api.js, WebProxyViewer
│   ├── package.json    #   Dependencies (xterm.js, React)
│   └── VERSION         #   Frontend version (1.0.0)
├── agent/              # Go CLI tunnel agent
│   ├── main.go         #   Login, list, connect commands
│   ├── go.mod          #   gorilla/websocket
│   └── VERSION         #   Agent version (1.0.0)
├── build-all.sh        # Linux/macOS build script (smart versioning)
├── build-all.ps1       # Windows build script (PowerShell)
├── run-dev.sh          # Dev launcher (backend + frontend)
├── VERSION             # Global version (1.0.0)
├── CHANGELOG.md        # Version history
└── LICENSE             # Source-Available License
```

---

## Quick Start

### Prerequisites

| Dependency | Required for |
|------------|-------------|
| **CMake** ≥ 3.16 | Backend build |
| **g++** / **clang++** (C++17) | Backend compilation |
| **SQLite3** (dev headers) | Database |
| **libssh2** (dev headers) | SSH terminal support |
| **Node.js** ≥ 18 | Frontend build |
| **Go** ≥ 1.25.8 | Agent build |

#### Install on Debian / Ubuntu / Kali

```bash
sudo apt install build-essential cmake libsqlite3-dev libssh2-1-dev nodejs npm golang
```

#### Install on macOS

```bash
brew install cmake sqlite libssh2 node go
```

### Build Everything

```bash
git clone https://github.com/NergYR/EndoriumFort.git
cd EndoriumFort
chmod +x build-all.sh
./build-all.sh
```

This will:
1. Build the C++ backend with CMake
2. Build the React frontend with Vite
3. Build the Go agent (native + cross-compiled for Linux/macOS/Windows)
4. Auto-increment versions only when source code actually changes
5. Create a git commit + tag if anything changed

### Run in Development

```bash
./run-dev.sh
```

Opens:
- **Backend** on `http://localhost:8080`
- **Frontend** on `http://localhost:5173` (Vite dev server with proxy)

### Default Login

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `Admin123` |

> Password is auto-hashed (SHA-256 + salt) on first login. Change it immediately.

---

## Usage

### Web Dashboard

1. Login at `http://localhost:5173`
2. **User console is access-first**:
  - open a resource tile and access it directly on the **same page**
  - web resources are rendered inline through the embedded bastion proxy view
  - SSH sessions and live terminal stay in the same workspace (no page switching)
3. **Access traceability**:
  - admins can enable a per-resource popup requiring **Access Reason** (and optional **Ticket ID**)
  - metadata is attached to bastion audit events for compliance and investigations
4. **Dual control and adaptive policy**:
  - admins can enforce **dual approval** per resource
  - operators submit access requests from the same connect modal (reason + optional ticket)
  - admins approve/deny from the built-in Access Requests queue
  - for high-risk adaptive resources, `ticketId` is enforced server-side
  - use **Access Playbook** actions in the access modal to save/apply recurring justification and purpose templates per resource
5. **Sessions** - Monitor, shadow (read-only), or terminate active sessions
  - monitor **Session SLO Insights** (completion rate, average duration, stale active sessions)
  - pin critical sessions in **Watchlist** to track state transitions (active/closed/errors) faster
  - each session card now shows effective routing path (`direct route` or `via relay`) with relay label/status when applicable
  - use **SSH Snippets Studio** to inject or execute recurring troubleshooting commands
  - save custom snippets per operator browser profile for faster interventions
  - open **Session DNA** to inspect integrity chain entries and verification status
6. **Audit** — Search and filter all security events
  - export the current filtered audit view as CSV for reporting and case evidence
7. **Recordings** — Replay past SSH sessions with the animated Asciinema player (admin/auditor)
8. **Admin dashboard** — Manage users/resources/permissions and view platform stats
  - includes **Relay Fabric** operations panel for distributed bastion control-plane:
    - live relay fleet inventory with online/offline status
    - per-resource relay assignment from the admin console
    - online-only assignment toggle to prevent accidental routing toward stale relays
    - direct relay bootstrap from UI with relay certificate + short-lived one-time enrollment token generation
    - runtime relay policy visibility (certificate policy, enrollment enabled, token TTL, stale threshold)
9. **Granular permissions**:
  - role gives a default permission baseline
  - admin can override each permission per user (`allow`, `deny`, or `inherit`)
  - admin UI includes a dedicated **Granular Action Permissions** panel per user
  - endpoints: `GET /api/users/:id/permissions`, `PUT /api/users/:id/permissions/:permission`
10. **Risk-aware access prompt**:
  - before access, operators get a live **Risk Preview** (`score`, `effectiveRiskLevel`, factors)
  - high/critical resources enforce **Session Purpose** at creation time
  - optional `purposeEvidence` can be attached for compliance context
11. **Live security notifications**:
  - the console raises real-time toast alerts when new critical audit signals are observed
  - currently includes auth anomalies, unjustified session creation, and behavior anomaly events
  - alerts auto-expire and can be dismissed manually
  - powered by dedicated API polling: `GET /api/security/alerts?sinceId=<id>`
  - incident escalation is audit-tracked via: `POST /api/security/incidents/escalate` (event type `security.incident.escalated`)
  - active incident case lifecycle APIs:
    - `GET /api/security/incidents/active`
    - `POST /api/security/incidents/open`
    - `POST /api/security/incidents/close`
  - escalation banner can open incident cases for SOC coordination and show active case metadata
  - escalation banner now correlates suspect sessions and provides one-click `Audit session` shortcuts
  - correlated sessions are ranked by a risk score (signal count, criticality, recency, active status)
  - operators with session permissions can terminate all active correlated suspects from a confirmation dialog
  - platform admins can enable/disable containment from the incident banner to enforce justifications globally
  - containment state API: `GET /api/security/containment` and `POST /api/security/containment`
  - while containment is active, backend blocks session creation without `justification` and emits `session.create.blocked.containment`
12. **Relay control-plane (distributed bastion foundations)**:
  - enroll relay nodes with a shared enrollment secret:
    - `POST /api/relays/enroll`
    - header: `X-EndoriumFort-Relay-Secret`
  - enroll relay nodes with an admin-issued short-lived one-time token:
    - `POST /api/relays/enroll`
    - header: `X-EndoriumFort-Relay-Enrollment-Token`
  - relay must present an admin-issued certificate for enrollment and heartbeat:
    - header: `X-EndoriumFort-Relay-Certificate`
  - mint relay certificates from admin API:
    - `POST /api/relays/certificate`
  - mint relay enrollment tokens from admin API:
    - `POST /api/relays/enrollment-token`
  - keep relay health fresh with heartbeat:
    - `POST /api/relays/heartbeat`
    - header: `X-EndoriumFort-Relay-Token`
  - list relay fleet health and metadata (admin):
    - `GET /api/relays`
  - inspect relay runtime control-plane settings (admin, secret never returned):
    - `GET /api/relays/config`
  - bind/unbind one resource to one relay (admin):
    - `POST /api/relays/assign`
  - resolve runtime path for a resource (direct or relay):
    - `GET /api/relays/resolve/:resourceId`
  - relay route automatically falls back to `direct` when assigned relay is stale/offline
  - relay enrollment/heartbeat routes require secure transport (`HTTPS`) except local loopback lab usage

### Relay Runtime Configuration

Set relay control-plane hardening values in backend runtime:

- `ENDORIUMFORT_RELAY_ENROLL_SECRET`: shared secret required by `POST /api/relays/enroll`
- `ENDORIUMFORT_RELAY_CERT_REQUIRED`: require relay certificate presentation on enroll/heartbeat (default `true`)
- `ENDORIUMFORT_RELAY_CERT_TTL_SECONDS`: admin-issued relay certificate TTL (default `2592000`)
- `ENDORIUMFORT_RELAY_ENROLL_TOKEN_TTL_SECONDS`: admin-issued one-time enrollment token TTL (default `600`)
- `ENDORIUMFORT_RELAY_TOKEN_TTL_SECONDS`: relay auth token TTL (default `86400`)
- `ENDORIUMFORT_RELAY_HEARTBEAT_STALE_SECONDS`: relay stale threshold for online/offline decision (default `90`)

If `ENDORIUMFORT_RELAY_ENROLL_SECRET` is not set, enrollment stays fail-closed (disabled).

### Agent Tunnel

For transparent access to web applications (no URL rewriting):

```bash
# Authenticate
./agent/endoriumfort-agent login \
  --server http://bastion:8080 \
  --user admin --password Admin123

# List available resources
./agent/endoriumfort-agent list \
  --server http://bastion:8080 --token <your-token>

# Open tunnel to resource #3 on local port 8888
./agent/endoriumfort-agent connect \
  --server http://bastion:8080 --token <your-token> \
  --resource 3 --local-port 8888

# Open multiple tunnels with one single agent instance
./agent/endoriumfort-agent connect \
  --server http://bastion:8080 --token <your-token> \
  --tunnel 3:8888 --tunnel 7:8890 --tunnel 10:8892

# Open multi-tunnel agent in live management mode
./agent/endoriumfort-agent connect \
  --server http://bastion:8080 --token <your-token> \
  --tunnel 3:8888 --manage
# then use: add 7:8890 | remove 8888 | list | stats | quit

# Live TUI monitoring (health + TX/RX)
./agent/endoriumfort-agent connect \
  --server http://bastion:8080 --token <your-token> \
  --tunnel 3:8888 --tunnel 7:8890 --tui

# Structured JSON logs
./agent/endoriumfort-agent connect \
  --server http://bastion:8080 --token <your-token> \
  --tunnel 3:8888 --log-json

# Browse http://127.0.0.1:8888 — traffic tunneled through bastion
```

Security note (agent tunnel hardening):
- The agent no longer sends long-lived auth tokens in WebSocket URL query parameters.
- Before opening each tunnel WebSocket, the agent requests a short-lived one-time ticket from `POST /api/tunnel/ticket`.
- The backend consumes this ticket on first use for replay resistance and tighter tunnel traceability.
- Tunnel tickets are IP-bound server-side (issued source IP must match WebSocket source IP).
- Tunnel auth now uses split credentials: one-time `ticket` plus one-time `proof` sent in WebSocket headers.
- Tunnel tickets are also bound to agent `User-Agent` to reduce cross-client replay opportunities.
- Tunnel handshake now requires a cryptographic HMAC-SHA256 proof-of-possession signature with `timestamp` + `nonce` headers.
- Ticket issuance now includes a server challenge that must be echoed in `X-EndoriumFort-Tunnel-Challenge` and included in the handshake signature payload.
- Ticket issuance now includes a rotating cryptographic key identifier (`signingKeyId`) that must be echoed in `X-EndoriumFort-Tunnel-Key-Id` and signed.
- Ticket issuance also includes a server HMAC attestation (`serverAttestation`) that must be echoed in `X-EndoriumFort-Tunnel-Attestation`.
- Backend rotates real in-memory signing secrets and verifies the attestation against current/previous secret windows.
- Backend enforces signature freshness window (`max skew`) to block delayed/replayed handshake frames.
- Backend now caches handshake nonces per ticket for a short TTL to reject duplicate nonce reuse attempts.
- Backend accepts only active key IDs (current plus short grace window) to support safe key rotation without breaking active clients.
- Tunnel ticket issuance is rate-limited per user to reduce abuse/bruteforce pressure.
- Agent transport policy is now strict by default: HTTPS/WSS required unless explicitly overridden for lab mode (`--allow-http` or `EF_ALLOW_INSECURE_HTTP=1`).
- A single running agent process can now host multiple concurrent local tunnels via repeated `--tunnel resource_id:local_port` options.
- With `--manage`, tunnels can be added/removed at runtime from the same process (`add`, `remove`, `list`, `quit`) without restarting the agent.
- Agent tracks per-tunnel health and traffic counters (`TX` / `RX` bytes), visible in `list`/`stats` manage commands and in `--tui` mode.
- Agent retries WebSocket establishment with exponential backoff + jitter for better resilience during transient network/backend failures.
- Agent can refresh token from `EF_TOKEN` or secure token file on auth failures to support token rotation with less downtime.
- Token file loading now enforces strict permissions (mode `600`) for better local secret hygiene.
- Optional `--log-json` enables structured logs for easier SIEM/observability pipelines.

Or simply **click a resource tile** with the agent protocol:

- the frontend generates an `endoriumfort://connect?...` deep-link (random local port)
- your browser proposes opening EndoriumFort Agent
- the agent starts the tunnel and redirects to the local URL automatically
- the modal still provides a fallback CLI command if protocol handler is not installed

### Agent Deep-Link Protocol (`endoriumfort://`)

The agent now supports browser deep-links to provide a one-click flow:

1. User clicks an `endoriumfort://connect?...` link in browser
2. OS opens `EndoriumFortAgent`
3. Agent starts the local tunnel
4. Agent opens/redirects browser to the target URL (typically local tunnel URL)

Deep-link format:

```text
endoriumfort://connect?server=https%3A%2F%2Fendorium.space&resource=2&local-port=35739&token=eft_xxx&redirect-url=http%3A%2F%2F127.0.0.1%3A%7B%7BLOCAL_PORT%7D%7D%2F
```

Supported query parameters:

- `server` (required)
- `resource` (required)
- `local-port` (optional, auto-allocated if omitted)
- `token` (optional if already available in `EF_TOKEN` or `~/.endoriumfort_token`)
- `redirect-url` (optional, defaults to `http://127.0.0.1:<local-port>`)
- `insecure=1` / `allow-http=1` for lab usage only

Template placeholders in `redirect-url`:

- `{{LOCAL_PORT}}`
- `{{RESOURCE_ID}}`
- `{{SERVER_URL}}`

Example fallback CLI invocation:

```bash
./agent/endoriumfort-agent open-link "endoriumfort://connect?server=https%3A%2F%2Fendorium.space&resource=2&local-port=35739"
```

#### Register protocol handler per OS

Linux:

```bash
chmod +x agent/installers/linux/install-protocol.sh
./agent/installers/linux/install-protocol.sh ./agent/endoriumfort-agent
```

macOS:

```bash
chmod +x agent/installers/macos/install-protocol.sh
./agent/installers/macos/install-protocol.sh ./agent/endoriumfort-agent-darwin-arm64
```

Windows (PowerShell):

```powershell
./agent/installers/windows/install-protocol.ps1 -AgentPath .\agent\endoriumfort-agent.exe
```

Uninstall scripts are available in the same folders (`uninstall-protocol.*`).

#### Build native installer packages

The repository now includes packaging scripts for native installers:

- Linux (`.deb` / `.rpm`): `agent/packaging/linux/build-packages.sh`
- macOS (`.pkg`): `agent/packaging/macos/build-pkg.sh`
- Windows (`.msi`): `agent/packaging/windows/build-msi.ps1`

Linux local build (requires `fpm`, `rpm`, and prebuilt Linux binaries in `release/`):

```bash
VERSION=1.1.0 bash agent/packaging/linux/build-packages.sh
```

macOS local build (requires `pkgbuild` and a Darwin binary):

```bash
VERSION=1.1.0 \
BINARY="$PWD/release/endoriumfort-agent-darwin-arm64" \
ARCH=arm64 \
bash agent/packaging/macos/build-pkg.sh
```

Windows local build (requires WiX CLI):

```powershell
dotnet tool install --global wix
.\agent\packaging\windows\build-msi.ps1 -Version 1.1.0 -BinaryPath .\release\endoriumfort-agent-windows-amd64.exe
```

Automated release packaging is handled by GitHub Actions workflow:

- `.github/workflows/release-agent.yml` (triggered on tag `v*`)
- uploads `.deb`, `.rpm`, `.pkg`, and `.msi` to the GitHub release
- supports optional signing when secrets are configured:
  - macOS notarization: `APPLE_NOTARY_APPLE_ID`, `APPLE_NOTARY_TEAM_ID`, `APPLE_NOTARY_PASSWORD`
  - Windows Authenticode: `WINDOWS_SIGN_PFX_BASE64`, `WINDOWS_SIGN_PFX_PASSWORD`

Continuous installer builds (for visibility on every change) are handled by:

- `.github/workflows/agent-installers-ci.yml` (push/PR on `dev` and `master`)
- publishes installer artifacts in the workflow run (`agent-installers-linux`, `agent-installers-macos`, `agent-installers-windows`)

---

## Security Features

| Feature | Details |
|---------|---------|
| **Password Hashing** | SHA-256 with random 128-bit salt, 10,000 iterations |
| **Token Expiration** | Bearer tokens expire after 1 hour, server-side invalidation |
| **Auth Cookie Security** | `HttpOnly` + `SameSite=Strict`; `Secure` automatically enabled on HTTPS deployments |
| **2FA / TOTP** | RFC 6238, QR code setup, compatible with Google Authenticator |
| **Authorization** | Action-level permissions (sessions/resources/audit/recordings/tunnel/SSH/RDP) with role defaults + per-user overrides |
| **Credential Vault** | SSH passwords stored in DB, never exposed in standard API |
| **Session Recording** | All SSH I/O recorded in Asciinema v2 format |
| **Audit Trail** | Every action logged to JSONL — login, logout, connect, shadow, proxy |

### WebSocket Auth Hardening

- SSH and shadow WebSocket connections now authenticate via secure cookie/header extraction on the backend.
- Frontend no longer appends auth token to WebSocket URLs, reducing token exposure in logs and browser history.
| **Cookie Auth** | HttpOnly cookies for web proxy, no tokens in URLs |

---

## Stability & Support (v1)

EndoriumFort is maintained with a v1-oriented support policy:

- Stable scope: SSH web terminal, HTTP/HTTPS proxy, agent tunnel, audit trail, session recording, RBAC/permission model, and 2FA/TOTP.
- Security support: only the latest tagged release is supported for security fixes (see `SECURITY.md`).
- Compatibility target: Linux-first deployments with official release assets for Linux/macOS/Windows agent binaries.
- Experimental or roadmap items remain explicitly marked in `## Roadmap` and are not covered by strict backward compatibility guarantees.

### Upgrade and Rollback

Minimal production-safe flow:

1. Backup persistent data (`ef-data` volume or SQLite DB + recordings).
2. Upgrade to the latest tag image/binaries.
3. Run health checks (`GET /api/health`) and a login/session smoke test.
4. If required, roll back to the previous tag and restore the backup.

---

## API Reference

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Authenticate (returns Bearer token) |
| `POST` | `/api/auth/logout` | Invalidate token server-side |
| `POST` | `/api/auth/change-password` | Change current user's password |
| `POST` | `/api/auth/setup-2fa` | Generate TOTP secret + QR URI |
| `POST` | `/api/auth/verify-2fa` | Verify and enable 2FA |
| `POST` | `/api/auth/disable-2fa` | Disable 2FA |
| `GET`  | `/api/auth/2fa-status` | Check 2FA status |

### Sessions

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/sessions` | List sessions (filterable) |
| `POST` | `/api/sessions` | Create new session (`resourceId`, `justification`, `ticketId`, optional `accessRequestId`) |
| `GET`  | `/api/sessions/:id` | Get session details |
| `POST` | `/api/sessions/:id/terminate` | Terminate session |
| `GET`  | `/api/sessions/stream` | SSE event stream |

### Resources

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`    | `/api/resources` | List resources (RBAC filtered) |
| `POST`   | `/api/resources` | Create resource (admin) |
| `PUT`    | `/api/resources/:id` | Update resource (admin) |
| `DELETE` | `/api/resources/:id` | Delete resource (admin) |
| `GET`    | `/api/resources/:id/credentials` | Get stored credentials (admin/auditor) |

### Access Requests

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/access-requests` | List access requests (admin/auditor: all, operator: own) |
| `POST` | `/api/access-requests` | Create access request (operator/admin) |
| `POST` | `/api/access-requests/:id/approve` | Approve request (admin) |
| `POST` | `/api/access-requests/:id/deny` | Deny request (admin) |

### Users & Permissions

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`    | `/api/users` | List users (admin) |
| `POST`   | `/api/users` | Create user (admin) |
| `PUT`    | `/api/users/:id` | Update user (admin) |
| `DELETE` | `/api/users/:id` | Delete user (admin) |
| `POST`   | `/api/users/:userId/resources/:resourceId` | Grant access |
| `DELETE` | `/api/users/:userId/resources/:resourceId` | Revoke access |

### WebSocket Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/ws/ssh` | Live SSH terminal |
| `/api/ws/shadow` | Session shadowing (read-only) |
| `/api/ws/rdp` | RDP session (requires FreeRDP) |
| `/ws/tunnel` | Agent TCP tunnel |

### Other

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/health` | Health check |
| `GET`  | `/api/stats` | Dashboard KPI metrics |
| `GET`  | `/api/audit` | Audit events |
| `GET`  | `/api/recordings` | List session recordings |
| `GET`  | `/api/recordings/:id/cast` | Download .cast file |
| `ANY`  | `/proxy/:resourceId/*` | HTTP reverse proxy |

---

## Docker Deployment

### Quick Start with Docker

```bash
# Pull and run the latest image
docker pull nergyr/endoriumfort:latest
docker run -d -p 80:80 \
  -v ef-data:/app/data \
  -v ef-recordings:/app/recordings \
  --name endoriumfort \
  nergyr/endoriumfort:latest
```

Then open `http://localhost` in your browser.

### Docker Compose

```bash
# Clone the repository
git clone https://github.com/NergYR/EndoriumFort.git
cd EndoriumFort

# Start with docker compose
docker compose up -d

# Customize port and timezone
EF_HTTP_PORT=8080 EF_HTTPS_PORT=8443 TZ=America/New_York docker compose up -d
```

### Docker Compose (Production)

```bash
# 1) Prepare production environment file
cp .env.prod.example .env.prod

# 2) Adjust .env.prod (domain, email, immutable tag, ports)

# 3) Start production stack
docker compose --env-file .env.prod -f docker-compose.prod.yml up -d

# Follow logs
docker compose --env-file .env.prod -f docker-compose.prod.yml logs -f
```

Alternative with helper script:

```bash
# first run auto-creates .env.prod from .env.prod.example if missing
./run-prod.sh start

# common operations
./run-prod.sh status
./run-prod.sh logs
./run-prod.sh update
./run-prod.sh stop
```

Production notes:
- Use immutable `DOCKER_TAG` values (avoid `latest`).
- Enable ACME only when DNS and ports 80/443 are correctly exposed.
- Keep volumes (`ef-data`, `ef-recordings`, `ef-letsencrypt`) persistent and backed up.

### Build from Source

```bash
docker compose build
docker compose up -d
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKER_IMAGE` | `nergyr/endoriumfort` | Docker Hub image name |
| `DOCKER_TAG` | `latest` | Image tag |
| `EF_HTTP_PORT` | `80` | Host HTTP port mapping |
| `EF_HTTPS_PORT` | `443` | Host HTTPS port mapping |
| `TZ` | `Europe/Paris` | Container timezone |
| `ACME_ENABLED` | `0` | Enable Let's Encrypt provisioning (`1` to enable) |
| `ACME_DOMAIN` | _(empty)_ | Public DNS name for certificate issuance |
| `ACME_EMAIL` | _(empty)_ | Contact email used by Let's Encrypt |

### Persistent Volumes

| Volume | Mount Point | Description |
|--------|-------------|-------------|
| `ef-data` | `/app/data` | SQLite database, configuration |
| `ef-recordings` | `/app/recordings` | Session recordings (.cast) |

### CI/CD — Docker Hub Publishing

A GitHub Actions workflow automatically builds and pushes the Docker image on every tag push (`v*`):

- **Docker Hub**: `nergyr/endoriumfort:<version>` + `:latest`
- **GHCR**: `ghcr.io/nergyr/endoriumfort:<version>` + `:latest`
- **GitHub Actions cache** for faster builds

Required secrets in GitHub repository settings:
- `DOCKERHUB_USERNAME` — Docker Hub username
- `DOCKERHUB_TOKEN` — Docker Hub access token

### Release Artifact Verification

For tag releases, verify checksums and signed bundles from release assets:

```bash
# 1) Verify checksums file integrity
sha256sum -c checksums-sha256.txt

# 2) Verify keyless signature bundle for checksums
cosign verify-blob \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer-regexp ".*" \
  --bundle checksums-sha256.txt.bundle.json \
  checksums-sha256.txt

# 3) Verify keyless signature bundle for repository SBOM
cosign verify-blob \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer-regexp ".*" \
  --bundle repository-sbom.cdx.json.bundle.json \
  repository-sbom.cdx.json
```

---

## Build System

EndoriumFort uses a **smart versioning system** based on SHA-256 hashing of source files:

- Each component (backend, frontend, agent) has its own `VERSION` file
- Versions only increment when source code actually changes
- A global `VERSION` at the root tracks the overall project version
- On each build, if any component changed, a git commit + tag is automatically created

```bash
# Full build with auto-versioning
./build-all.sh          # Linux / macOS
./build-all.ps1         # Windows (PowerShell)

# Development mode (backend + frontend with hot reload)
./run-dev.sh
```

### Cross-Compilation

The build scripts automatically cross-compile the agent:

| Host | Agent binaries produced |
|------|------------------------|
| Linux amd64 | `endoriumfort-agent` (linux) + `.exe` (windows) + macOS arm64 |
| macOS arm64 | `endoriumfort-agent` (macOS) + `.exe` (windows) + linux amd64 |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | C++17, [Crow](https://crowcpp.org/) 1.2, SQLite3, libssh2, Asio |
| **Frontend** | React 18, Vite 7, [xterm.js](https://xtermjs.org/) v6 |
| **Agent** | Go 1.25.8, [gorilla/websocket](https://github.com/gorilla/websocket) |
| **Build** | CMake 3.16+, npm, Go toolchain |
| **Database** | SQLite3 (file-based, zero config) |
| **Protocols** | SSH, HTTP/HTTPS, RDP (FreeRDP), VNC (planned), TCP tunnel |

---

## Roadmap

- [x] SSH terminal with recording & replay
- [x] HTTP/HTTPS transparent proxy
- [x] Agent-based TCP tunneling
- [x] 2FA / TOTP authentication
- [x] Credential vault with auto-injection
- [x] Session shadowing (live observation)
- [x] Dashboard KPIs & statistics
- [x] Smart per-component versioning
- [ ] AES-256 encryption for vault passwords
- [ ] Rate limiting & brute-force protection
- [ ] CSP headers & security hardening
- [ ] Anomaly detection & alerting
- [ ] LDAP / Active Directory integration
- [ ] VNC protocol support
- [x] Docker deployment
- [ ] Cluster / HA mode

---

## License

This project is released under the **EndoriumFort Source-Available License v1.0**.

**You are free to:**
- Use the software for personal, educational, or commercial purposes
- Redistribute verbatim copies with attribution

**You must:**
- **Cite this repository** in any use: [github.com/NergYR/EndoriumFort](https://github.com/NergYR/EndoriumFort)

**You may not:**
- Modify, alter, or create derivative works
- Sublicense or relicense under different terms

See [LICENSE](LICENSE) for full terms.

---

## Contributing

Contributions via pull requests are welcome! Since the license does not allow derivative works, contributions must be submitted back to the original repository.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Author

**NergYR** — [github.com/NergYR](https://github.com/NergYR)

---

<p align="center">
  <strong>EndoriumFort</strong> — Secure your infrastructure, audit everything.
</p>
