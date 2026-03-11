# Changelog

## v1.1.0-dev - 2026-03-11
### Distributed Bastion Foundations
- Added **Relay Control Plane (v1)** backend routes for secure relay-node lifecycle and resource routing decisions.
- Added relay enrollment endpoint `POST /api/relays/enroll` guarded by `X-EndoriumFort-Relay-Secret`.
- Added one-time short-lived relay enrollment token flow:
  - admin issuance endpoint `POST /api/relays/enrollment-token`
  - relay enrollment support via `X-EndoriumFort-Relay-Enrollment-Token`
- Added relay certificate issuance and validation flow:
  - admin issuance endpoint `POST /api/relays/certificate`
  - relay enrollment/heartbeat now support certificate presentation via `X-EndoriumFort-Relay-Certificate`
  - relay cert can be bound to relay identity and expires automatically by TTL policy
- Added relay heartbeat endpoint `POST /api/relays/heartbeat` guarded by `X-EndoriumFort-Relay-Token` to maintain online/offline status.
- Added admin relay inventory endpoint `GET /api/relays` with relay health, capability, and metadata visibility.
- Added admin resource-binding endpoint `POST /api/relays/assign` to assign or clear one relay per resource.
- Added route-resolution endpoint `GET /api/relays/resolve/:resourceId` with automatic direct fallback when relay is missing or stale.
- Added relay in-memory control-plane state in `AppContext` (fleet map, resource bindings, token TTL, heartbeat stale window).
- Added runtime relay hardening via environment variables:
  - `ENDORIUMFORT_RELAY_ENROLL_SECRET`
  - `ENDORIUMFORT_RELAY_CERT_REQUIRED`
  - `ENDORIUMFORT_RELAY_CERT_TTL_SECONDS`
  - `ENDORIUMFORT_RELAY_ENROLL_TOKEN_TTL_SECONDS`
  - `ENDORIUMFORT_RELAY_TOKEN_TTL_SECONDS`
  - `ENDORIUMFORT_RELAY_HEARTBEAT_STALE_SECONDS`
- Added admin visibility endpoint `GET /api/relays/config` (configuration metadata only, secret excluded).
- Added **Admin Relay Fabric UI** in `frontend/src/App.jsx` for:
  - relay fleet visibility (status, metadata, managed resource count)
  - per-resource relay assignment controls with direct fallback option
  - online-only relay assignment toggle to reduce accidental selection of stale/offline relays
  - relay certificate generation and copy workflow for secure relay bootstrap
  - direct relay enrollment token generation with copy-ready bootstrap command
  - runtime relay configuration visibility (certificate policy, enrollment enabled, TTL, stale threshold)
- Added relay control-plane frontend API clients in `frontend/src/api.js` and dedicated styling in `frontend/src/styles.css`.
- Added session-card relay path hints (`direct route` vs `via relay`) with relay label/status visibility in the Sessions workspace.

### Session Operations UX
- Added **SSH Snippets Studio** in the live terminal panel (`frontend/src/App.jsx`).
- Introduced prebuilt operational snippets (health snapshot, network checks, disk pressure, top processes) with one-click inject/run actions.
- Added custom snippet creation and deletion with browser-local persistence for each operator workstation.
- Styled and made responsive the snippet workspace (`frontend/src/styles.css`) for desktop and mobile operators.
- Added **Access Playbooks** in the connection justification modal with per-resource save/apply/delete actions.
- Access Playbooks persist locally in the browser and prefill reason/ticket/purpose fields for faster compliant access flows.
- Added **Critical Session Watchlist** with pin/unpin controls directly on session cards.
- Added dedicated watchlist alert stream for watched session status transitions.
- Added watchlist panel in sessions workspace with compact monitored session view and mobile-responsive layout.
- Added **Audit CSV Export** for the currently filtered audit timeline directly from the audit panel.
- Added **Session SLO Insights** panel in Sessions workspace (completion rate, average closed-session duration, stale active sessions).

## v1.0.0 - 2026-03-10
### General Availability
- Declared EndoriumFort `v1.0.0` as the first stable GA release.
- Aligned root and component version files to `1.0.0` (`VERSION`, `backend/VERSION`, `frontend/VERSION`, `agent/VERSION`, `frontend/package.json`).
- Consolidated release readiness baseline after CI hardening, CodeQL fixes, keyless Cosign verification updates, and signed artifact pipeline stabilization.

## v0.5.29 - 2026-03-10
### Go Toolchain Security Baseline
- Upgraded Go toolchain baseline to `1.25.8` for the agent and CI pipelines to address standard-library vulnerabilities reported by `govulncheck` (`GO-2026-4601`, `GO-2026-4602`).
- Updated workflows using Go (`ci.yml`, `release-gate.yml`, `release-agent.yml`, `codeql.yml`) to use `actions/setup-go` with `1.25.8`.
- Updated `agent/go.mod` toolchain directive and README references to match the new minimum Go version.
- Reworked token generation in `backend/src/app_context.cc` to remove offset-based `snprintf` chaining and fix CodeQL alert `cpp/overflowing-snprintf`.
- Removed remaining `snprintf` formatting in backend (`crypto.h`, `totp.h`, `session_recording.cc`, `main.cc.bak`) to prevent additional `cpp/overflowing-snprintf` findings.

## v0.5.25 - 2026-03-10
### GitHub Actions Reliability
- Docker publish workflow now creates Cosign attestations with explicit `--type slsaprovenance`, matching the attestation verification gate.
- CodeQL upload category now uses a unique namespace (`/endoriumfort-codeql/...`) to avoid category collisions with other code-scanning workflows on the same commit.

## v0.5.24 - 2026-03-10
### Final CI/Container Compatibility Fixes
- Frontend unit test command is now Node 20 compatible in CI by using an explicit test file path (`node --test ./test/api.test.mjs`) instead of a shell-dependent glob.
- Docker image backend build now explicitly sets `-DBUILD_TESTING=OFF` to prevent test target resolution failures in container build contexts that only copy runtime sources.

## v0.5.22 - 2026-03-10
### CI/Release Stabilization
- CI backend build now compiles both `endoriumfort_backend` and `endoriumfort_backend_tests` before running `ctest`, avoiding missing-test executable failures in clean runners.
- Release agent Cosign blob verification now includes explicit keyless certificate identity/issuer constraints for checksums, binary signature, and SBOM verification.
- Docker publish workflow now degrades gracefully when Docker Hub secrets are absent:
  - Docker Hub login is conditional
  - Docker Hub tags/sign/attest/verify are conditional
  - GHCR publication, signing, and attestation remain enforced

## v0.5.21 - 2026-03-09
### Security UX: Live Notification Stream
- Added in-app **live security toast notifications** in the main console.
- New high-signal audit events now raise immediate user-facing alerts:
  - authentication anomalies (`auth.login.failure`, `auth.rate_limit`)
  - unjustified session openings (`session.create.unjustified`)
  - behavior anomaly signals (`behavior.anomaly.*`)
- Alerts include event type + relative timestamp, support manual dismiss, and auto-expire to reduce noise.
- Live toast delivery now includes **priority ordering + per-type throttling** to surface critical signals first and suppress repetitive noise.
- Added operator-selectable live-alert filter modes (`strict`, `normal`, `permissive`) with persisted preference.
- Added **severity-aware display caps** (e.g., warning and critical limits) to avoid UI flood while preserving high-priority visibility.
- Added automatic **incident escalation banner** when multiple critical signals are detected within a short rolling window.
- Added backend escalation audit endpoint and event:
  - `POST /api/security/incidents/escalate`
  - emits `security.incident.escalated` for end-to-end incident traceability
- Live escalation banner now correlates and surfaces suspicious session IDs with direct audit shortcuts.
- Correlated suspect sessions are now prioritized by a computed risk score.
- Added `Terminate active suspects` action (confirmation-gated, permission-aware) from incident escalation banner.
- Added incident-driven **Containment Mode** toggle (admin) with new backend APIs:
  - `GET /api/security/containment`
  - `POST /api/security/containment`
- While containment is enabled, session creation now requires `justification` server-side and emits `session.create.blocked.containment` when denied.
- Added active incident lifecycle APIs for explicit SOC case management:
  - `GET /api/security/incidents/active`
  - `POST /api/security/incidents/open`
  - `POST /api/security/incidents/close`
- Escalation banner now supports opening and closing incident cases and displays active case metadata.
- Added dedicated backend endpoint for incremental live alert retrieval:
  - `GET /api/security/alerts?sinceId=<id>`

### Bastion-Agent Hardening: One-Time Tunnel Tickets
- Removed token-in-URL tunnel authentication path for bastion-agent WebSocket connections.
- Added one-time short-lived ticket issuance endpoint for tunnel establishment:
  - `POST /api/tunnel/ticket`
- Tunnel WebSocket now requires `ticket` + `resource_id` and consumes the ticket on first use (anti-replay).
- Added new audit event `security.tunnel.ticket.issued` for tunnel ticket traceability.
- Updated Go bastion-agent flow to request a fresh tunnel ticket for each local connection before opening WebSocket.
- Tunnel ticket usage is now source-IP bound (issuance IP must match WebSocket handshake IP).
- Added split tunnel authenticator model:
  - ticket endpoint now returns `ticket` + `proof`
  - WebSocket tunnel handshake requires the one-time proof in `X-EndoriumFort-Tunnel-Proof`
- Tunnel ticket validation now binds to agent `User-Agent` for stronger replay resistance.
- Added cryptographic challenge-response validation for WebSocket tunnel handshake:
  - agent sends `X-EndoriumFort-Tunnel-Timestamp`, `X-EndoriumFort-Tunnel-Nonce`, `X-EndoriumFort-Tunnel-Signature`
  - backend verifies HMAC-SHA256 signature derived from one-time tunnel proof material
  - backend rejects stale signatures beyond strict skew window to reduce delayed replay risk
- Added server-issued tunnel challenge (`challenge`) to ticket response and mandatory `X-EndoriumFort-Tunnel-Challenge` echo at handshake time.
- Added backend nonce replay cache (ticket+nonce short TTL) to reject duplicate handshake nonce reuse attempts.
- Added tunnel signing key-ID agility model:
  - ticket response now includes `signingKeyId`
  - agent sends `X-EndoriumFort-Tunnel-Key-Id`
  - backend accepts only active key IDs (current + grace) to allow safe key rotation windows
- Added server-side cryptographic attestation layer:
  - ticket response now includes `serverAttestation`
  - agent sends `X-EndoriumFort-Tunnel-Attestation`
  - backend verifies attestation against rotating in-memory signing secrets (current + previous grace window)
  - attestation is included in the agent handshake signature payload for stronger binding
- Added per-user tunnel ticket issuance throttling with dedicated events:
  - `security.tunnel.ticket.rate_limited`
  - `security.tunnel.ticket.rejected`
- Agent now enforces strict transport policy by default (HTTPS/WSS), with explicit lab override only (`--allow-http` / `EF_ALLOW_INSECURE_HTTP=1`).
- Agent now supports multi-tunnel mode in a single process instance:
  - repeated `--tunnel <resource_id>:<local_port>` on `connect`
  - one Ctrl+C cleanly stops all active local tunnel listeners
- Added optional live tunnel management mode (`--manage`) on `connect`:
  - `add <resource_id>:<local_port>` to start a new tunnel at runtime
  - `remove <local_port>` to stop one tunnel without stopping others
  - `list` to display active tunnels
  - `stats` to display active tunnels with TX/RX counters and state
  - `quit` to stop all tunnels and exit cleanly
- Added tunnel health and telemetry in the agent runtime:
  - tunnel state lifecycle (`starting`, `healthy`, `degraded`, `down`, `stopped`)
  - per-tunnel counters for total/active connections and TX/RX bytes
- Added optional TUI mode (`--tui`) for live tunnel supervision from a single process.
- Added optional structured logging mode (`--log-json`) for machine-consumable agent logs.
- Added WebSocket connect resiliency with exponential backoff + jitter on tunnel connection establishment.
- Added token rotation assist on auth failures by refreshing token from `EF_TOKEN` or secure local token file.
- Hardened local secret handling: token file is now read only if permissions are strict (`600`), and interactive password input uses best-effort byte zeroization after use.

### Release Readiness Gates
- Added `Release Gate` workflow for PRs with blocking checks:
  - changelog/migration enforcement for runtime-impacting changes
  - backend build + tests
  - frontend unit tests + build
  - frontend Playwright login e2e smoke
  - agent tests + build
  - supply-chain checks (`npm audit`, `govulncheck`, SBOM generation)
  - `docker compose` smoke startup + health check
- Agent release workflow now signs release artifacts using Sigstore Cosign keyless signatures:
  - signed `checksums-sha256.txt`
  - signed `endoriumfort-agent-linux-amd64` sample binary attestation
- Docker publish workflow now signs pushed container images (Docker Hub + GHCR) with Cosign keyless signatures and performs in-pipeline signature verification.
- Docker publish workflow now emits and verifies Cosign keyless attestations (`verify-attestation`) for image provenance validation.
- Agent release workflow now also generates a CycloneDX SBOM and publishes it as signed release artifacts (`repository-sbom.cdx.json` + signature + certificate).
- Release Gate now publishes diagnostics artifacts systematically (backend test logs, frontend unit logs, e2e logs/reports, compose smoke logs) to speed up incident triage.
- Release Gate supply-chain checks now include keyless SBOM signature generation + verification before publishing artifacts.

## v0.5.20 - 2026-03-09
### Bastion Innovation: Session DNA + Purpose-Bound Access + Risk Preview
- Added backend **Session DNA** chain storage and APIs for tamper-evident per-session lineage:
  - `GET /api/sessions/:id/dna`
  - chain entries include `prev_hash`, `payload_hash`, `chain_hash`
  - verification result returned to detect integrity mismatches
- Added backend **risk preview** endpoint:
  - `POST /api/sessions/risk-preview`
  - computes score and effective risk level from resource profile and contextual inputs
- Added **purpose-bound policy** for high/critical-risk resources:
  - session creation now supports `purpose` and `purposeEvidence`
  - high/critical resources require `purpose` server-side
- Frontend integration:
  - access prompt now shows live risk preview and factors
  - access prompt captures purpose and optional evidence
  - sessions panel includes **Session DNA** modal viewer with integrity status

## v0.5.19 - 2026-03-09
### Admin UX: Granular Permission Management Panel
- Added a new **Granular Action Permissions** section in the Admin user-permission panel.
- Admins can now manage per-user permission overrides directly from the UI with `inherit`, `allow`, or `deny` for each action-level permission.
- Resource assignment and action-level permission management are now loaded together when selecting a user.
- Permission override updates now refresh effective permission state in-place after each change.

## v0.5.18 - 2026-03-09
### Security Model: Granular Permission Overrides
- Added a permission catalog for backend authorization checks (sessions/resources/users/audit/recordings/tunnel/proxy/SSH/RDP/ephemeral credentials).
- Added per-user permission overrides in SQLite:
  - table: `user_permission_overrides`
  - effects: `allow`, `deny`, `inherit` (delete override)
- Added new admin APIs:
  - `GET /api/users/:id/permissions`
  - `PUT /api/users/:id/permissions/:permission`
- Login response now includes effective permissions for the authenticated user.

### Backend Authorization Migration
- Migrated major backend route guards from role-only checks to permission checks.
- Updated SSH, RDP, tunnel, and proxy gates to rely on permission evaluation.
- Preserved role aliases and role baselines for compatibility, while enabling fine-grained per-user exceptions.

### Frontend Authorization Behavior
- Frontend capabilities now consume backend-provided `permissions` from login payload.
- Added compatibility fallback to role-based capabilities when no permissions are present.

### Validation
- Runtime smoke test verified with `admin/admin`:
  - login success
  - resource creation success
  - ephemeral lease issue success
  - ephemeral lease consume success

## v0.5.17 - 2026-03-09
### UX Refactor: Access-First User Console
- Removed command palette workflow from user console.
- Removed user-facing innovation-lab flow from primary navigation.
- User experience now centers on **single-page direct access**:
  - resources remain visible while operating
  - web resources open inline in an embedded proxy frame
  - SSH live console remains in-place (no route changes needed)
- User-facing platform stats removed from the regular console.
- Platform stats moved to the **Admin dashboard**.

### Bastion Innovation: Access Justification Trail
- Session creation now supports optional:
  - `justification`
  - `ticketId`
- These fields are attached to `session.create` audit payloads.
- New audit signal: `session.create.unjustified` is emitted when a session is opened without a reason.
- Admins can now enable a per-resource policy: `requireAccessJustification`.
- When enabled, operators must provide a reason in a connect popup before session start.
- Backend now enforces this policy server-side when `resourceId` is provided at session creation.

### Bastion Innovation: Dual Control, Adaptive Policy, and Guard Rails
- Added per-resource governance flags:
  - `requireDualApproval`
  - `enableCommandGuard`
  - `adaptiveAccessPolicy`
  - `riskLevel` (`low`, `medium`, `high`, `critical`)
- New dual-control API:
  - `GET /api/access-requests`
  - `POST /api/access-requests`
  - `POST /api/access-requests/:id/approve`
  - `POST /api/access-requests/:id/deny`
- Session creation now enforces approved `accessRequestId` when dual approval is enabled on the target resource.
- Adaptive policy now enforces `ticketId` on high/critical resources for non-admin operators.
- SSH command guard now blocks high-risk command patterns and emits `command_guard.block` audit events.
- Session close now updates user behavior baseline and emits `behavior.anomaly.command_spike` when command volume deviates strongly from historical averages.
- Recording closure now emits a lightweight `recording.watermark` audit marker.

### Files Updated
- `frontend/src/App.jsx`: user flow redesign, inline web access, admin stats placement, resource-level justification popup
- `backend/src/routes.cc`: session policy enforcement + access request routes + resource governance fields
- `backend/src/app_context.cc`, `backend/src/models.h`, `backend/src/utils.h`: resource policy persistence, access-request persistence, behavior telemetry
- `backend/src/ssh.cc`: command guard, runtime input counters, recording watermark audit event
- `README.md`: updated usage model and bastion feature set

## v0.5.16 - 2026-03-06
### UX Redesign: Mission Board + Command Palette (Option B)
- **Radical navigation change**:
  - removed tab/rail-style workspace navigation from the main console
  - introduced a **Mission Board** with large stage cards for context switching
  - each card exposes stage, mission intent, and keyboard shortcut (`Alt+1..5`)
- **Command Palette introduced**:
  - open with `Ctrl/Cmd+K`
  - fuzzy-search command list for workspace jumps and operational actions
  - direct commands for refresh, admin access, theme toggle, password flow, and logout
- **Keyboard-first flow**:
  - `Alt+1..5` quick workspace switching
  - `Escape` closes command palette

### Files Updated
- `frontend/src/App.jsx`: mission board navigation, command palette state/actions, keyboard shortcuts
- `frontend/src/styles.css`: mission board, command palette, responsive and dark-mode styling
- `README.md`: navigation and usage model updated

## v0.5.15 - 2026-03-06
### UX Redesign: Workflow-First Navigation
- **Navigation model replaced**: moved from flat tab strip to a **workflow rail** with staged workspaces:
  - Stage 1: Command Deck
  - Stage 2: Live Access
  - Stage 3: Investigation
  - Stage 4: Evidence Replay
  - Stage 5: Innovation Lab
- **Context panel added**: each workspace now exposes current mission context, objective hint, and immediate actions.
- **Action decluttering**: removed duplicated top-level quick jumps (audit/recordings) and consolidated key actions in the workspace brief.
- **Responsive behavior improved**: workflow rail adapts into compact grid/stack on tablet and mobile.

### Files Updated
- `frontend/src/App.jsx`: workflow rail state mapping, contextual brief, header action simplification
- `frontend/src/styles.css`: new workflow layout/components + responsive/dark-mode support
- `README.md`: usage flow and navigation documentation updated

## v0.5.14 - 2026-03-06
### Security Hardening: Auth Transport and WebSocket Hygiene
- **Auth cookie hardened at login/logout**:
  - `HttpOnly` session cookie for `endoriumfort_token`
  - `SameSite=Strict` by default
  - `Secure` automatically applied when request is HTTPS (via forwarded proto/origin/referer detection)
  - logout and password-change now explicitly clear the auth cookie
- **WebSocket token leakage reduced**:
  - frontend no longer sends auth token in WebSocket query strings for `/api/ws/ssh` and `/api/ws/shadow`
  - backend WebSocket auth now uses centralized header/cookie token extraction
- **Token extraction centralized**:
  - shared helpers introduced for bearer/cookie parsing, HTTPS detection, and auth-cookie creation/clearing
  - proxy/tunnel/RDP paths aligned to favor header/cookie auth over legacy query-token patterns

### Files Updated
- `backend/src/utils.h`: secure auth helpers (`extract_auth_token_from_request`, cookie parsing, cookie builders)
- `backend/src/routes.cc`: secure cookie set/clear + no-store cache directive on auth routes
- `backend/src/app_context.cc`: centralized auth token extraction usage
- `backend/src/ssh.cc`, `backend/src/tunnel.cc`, `backend/src/rdp.cc`: WebSocket auth extraction hardening
- `backend/src/http_proxy.cc`: auth-token extraction path tightened (header/cookie first)
- `frontend/src/App.jsx`: removed WS token query parameters for SSH and shadow sockets

## v0.5.13 - 2026-03-06
### Feature: RBAC Clarity and Console Orientation
- **RBAC clarity pass** with explicit role naming in UI:
  - `Platform Admin` (governance), `Session Operator` (operations), `Security Auditor` (traceability)
  - Added a dedicated **RBAC Blueprint** panel in the Admin Console with role descriptions and permission scope
- **Backend role alias compatibility**:
  - API now accepts and normalizes aliases such as `platform_admin`, `session_operator`, `security_auditor`
  - Existing role checks remain backward compatible through centralized normalization helpers
- **Console orientation improvement**:
  - Added a **Tab Compass** strip under the navbar to explain the objective of each workspace
  - Upgraded tab labels with action-oriented context (`Plan`, `Operate`, `Trace`, `Replay`, `Explore`)

### Fixes
- **Permission UX consistency**: session actions in the UI are now disabled when the current role cannot operate sessions
- **Role-aware filtering consistency**: audit and recordings visibility now rely on capability checks instead of scattered string comparisons

### Files Updated
- `backend/src/utils.h`: role normalization helpers and role-aware permission checks
- `backend/src/routes.cc`: role checks migrated to normalized helpers; user role persistence normalized
- `backend/src/http_proxy.cc`, `backend/src/tunnel.cc`, `backend/src/ssh.cc`, `backend/src/rdp.cc`: normalized role checks for access gates
- `frontend/src/App.jsx`: capability helpers, role labels, tab compass, RBAC blueprint panel, role-aware action gating
- `frontend/src/styles.css`: styles for enhanced tabs, tab compass, and RBAC cards
- `README.md`: documentation updates for role model and workspace orientation

## v0.5.12 - 2026-03-06
### Feature: Tabbed Console Navigation Redesign
- **Major UI refactor**: main console moved from toggled cards to a **persistent tabbed navbar** model
  - Tabs: `Overview`, `Sessions`, `Audit`, `Recordings`, `Innovation Lab`
  - Improved operator flow: no more hide/show card juggling while investigating incidents
- **Audit and recordings become first-class workspaces** with dedicated tabs and auto-refresh on tab entry
- **Cross-tab actions**: session actions can jump directly to audit/recordings context

### Feature: Innovation Lab
- **Smart Launcher**: unified search to find and connect resources by name/target/protocol
- **Resource Favorites**: pin preferred resources with local persistence (`localStorage`)
- **Exposure Analytics**: protocol distribution + runtime risk index based on resources and active sessions

### Frontend Changes
- `frontend/src/App.jsx`: added tab state machine, tab-aware data loading, innovation modules, and refactored main rendering flow
- `frontend/src/styles.css`: added navbar/tab UI styles, innovation panel styles, and responsive/dark mode variants

## v0.5.11 - 2026-03-06
### Feature: Security Operations Dashboard Enhancements
- **New: Security Center panel** on the main console with live posture cards:
  - Login failures in the last 30 minutes
  - Long-running active sessions detection
  - Admin changes over 24h (resource/user governance activity)
  - MFA posture visibility (enabled/disabled)
- **New: Background security feed polling** (admin/auditor) from audit logs every 20s for near-real-time anomaly hints
- **New: Quick Refresh action** in top navigation to synchronize sessions, resources, stats, users (admin), and audit feed in one click
- **New: Recent Sessions panel** with last opened sessions, relative timestamps, and direct intervention actions (Terminate/Audit)
- **Responsive + dark mode support** added for all new dashboard panels

### Frontend Changes
- `frontend/src/App.jsx`: Added security feed state, polling logic, quick refresh workflow, derived security signals, and new dashboard sections
- `frontend/src/styles.css`: Added styles for Security Center and Recent Sessions, plus responsive and dark-theme variants

## v0.5.0 - 2025-07-17
### Feature: Docker & Production Deployment
- **Docker multi-stage build**: 3-stage Dockerfile (C++ backend build → React frontend build → production image with nginx)
- **docker-compose.yml**: Single-service deployment with configurable env vars (`EF_PORT`, `TZ`, `DOCKER_IMAGE`, `DOCKER_TAG`), persistent volumes (`ef-data`, `ef-recordings`)
- **Docker Hub CI/CD**: GitHub Actions workflow (`docker-publish.yml`) auto-builds and pushes on tag `v*` to Docker Hub (`nergyr/endoriumfort`) and GHCR, with GHA build cache
- **Production deployment script**: `deploy-prod.sh` with systemd service, Nginx reverse proxy, TLS support (Let's Encrypt / self-signed), multi-distro (apt/dnf/yum)
- **Agent release workflow**: GitHub Actions (`release-agent.yml`) cross-compiles Go agent for 5 targets on tag push, creates GitHub Release with checksums
- **Build tag safety**: Tags are no longer force-overwritten; build scripts check existence before creating

### New Files
- `Dockerfile` — Multi-stage production build
- `docker/entrypoint.sh` — Container entrypoint (backend + nginx, health check, graceful shutdown)
- `docker/nginx.conf` — Nginx reverse proxy config (API, WebSocket, web proxy, SPA fallback)
- `docker-compose.yml` — Docker Compose service definition
- `.dockerignore` — Build context exclusions
- `.github/workflows/docker-publish.yml` — Docker Hub & GHCR publishing workflow
- `.github/workflows/release-agent.yml` — Agent release workflow
- `deploy-prod.sh` — Production deployment script (Linux)

### UI Changes
- **Logo integration**: Full blue logo on login page, icon dark logo in headers and as favicon
- **Brand identity**: `.brand-logo` with hover animation, dark mode inversion

## v0.4.0 - 2025-07-17
### Security: Comprehensive Security Hardening
- **Security headers middleware**: X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy, Cache-Control, Permissions-Policy applied on every response via Crow middleware
- **Rate limiting**: Sliding window (10 attempts / 5 min) on login endpoint with 429 response and audit event
- **CSPRNG token generation**: `/dev/urandom` 256-bit tokens with `eft_` prefix (replaces mt19937_64)
- **SSRF protection**: Blocks loopback, link-local, metadata IPs on resource creation/update
- **RBAC enforcement**: Sessions (admin/auditor/operator), Stats (admin/auditor), Web resources filtered by permissions
- **Input validation**: Protocol whitelist (ssh/rdp/vnc/http/https/agent), length limits (name 255, target 255, description 1024), imageUrl validation
- **Token rotation**: All user tokens invalidated on password change
- **JSON injection fix**: `json_escape()` applied to all audit log dynamic fields
- **DNS resolution**: Thread-safe `getaddrinfo()` replaces `gethostbyname()` in proxy and tunnel
- **Token leak prevention**: Tokens masked in logs (first 8 chars + `...`), removed from proxy URL responses
- **Default admin hardening**: Password changed from "admin" to "Admin123" with security warning log
- **Frontend security**: Relative proxy URLs (no token in URL), iframe sandbox `allow-top-navigation-by-user-activation`
- **Agent security**: `EF_TOKEN`/`EF_PASSWORD` env vars, token file `~/.endoriumfort_token` (0600), TLS warning, masked token output

### New Files
- `SECURITY.md`: Full security policy with vulnerability table, RBAC matrix, deployment recommendations
- `security_middleware.h`: Crow middleware struct + `CrowApp` type alias

### Backend Changes
- `main.cc`: Uses `CrowApp` (middleware-enabled) instead of `crow::SimpleApp`
- `app_context.h`: `RateLimitEntry`, rate limit fields, `invalidate_user_tokens()`, `check_rate_limit()`, `is_safe_target()`
- `app_context.cc`: CSPRNG `generate_token()`, rate limiter, SSRF checker, token invalidation
- `routes.cc`: Rate limiting, RBAC checks, input validation, protocol whitelist, SSRF guards
- `http_proxy.cc`: `getaddrinfo()`, JSON escaping, permission filtering, token removed from response
- `tunnel.cc`: `getaddrinfo()`, token masking, JSON escaping
- `ssh.cc`: Token masking in logs

### Frontend Changes
- `WebProxyViewer.jsx`: Relative URLs, hardened iframe sandbox

### Agent Changes
- `main.go`: `warnIfInsecure()`, `EF_TOKEN`/`EF_PASSWORD` env vars, token file storage, masked output

## v0.3.0 - 2026-02-28
### Feature: Credential Vault (Coffre-fort d'identifiants)
- **New: SSH credential storage** on resources (`sshUsername`, `sshPassword`)
  - Credentials stored in SQLite, password never exposed in standard API responses
  - Dedicated `GET /api/resources/<id>/credentials` endpoint with audit logging
  - Only admin and auditor roles can retrieve stored credentials
- **Auto-injection**: SSH connections auto-fill username/password from vault when available
  - `hasCredentials` boolean in resource API for UI indication
  - Resource tiles show 🔐 vault pill when credentials are stored
- **Admin form**: SSH Username & Password fields in resource creation/edit (SSH protocol)

### Feature: Dashboard Statistics
- **New: `GET /api/stats` endpoint** — Aggregated metrics refreshed every 15 seconds
  - Active sessions, total sessions, resource count (by protocol)
  - User count, recording count, active token count
- **Frontend: Stats grid** — 6 KPI cards with icons and gradient accents
  - Animated hover effects, dark mode variants
  - Real-time polling with 15-second interval

### Feature: Animated Asciinema Player
- **New: xterm.js-based session replay** replaces static text dump
  - Parses .cast files and replays events with real timing (capped at 2s per delay)
  - Play / Pause / Close controls
  - Full terminal emulation during playback

### Feature: Audit Search & Filters
- **Text search**: Filter audit events by keyword across all fields
- **Type filter**: Dropdown to filter by event type (auth.login, session.open, etc.)
- Filters combine for precise audit investigation

### Feature: Session Shadowing (Live Observation)
- **New: WebSocket `/api/ws/shadow`** for real-time read-only session observation
  - Authentication required (Bearer token via query param)
  - Restricted to admin and auditor roles
  - Audit event `session.shadow` logged on each shadow connection
- **Backend broadcast**: SSH reader thread forwards output to all shadow watchers
  - Thread-safe with dedicated mutex on `shadow_connections` map
  - Automatic cleanup on disconnect
- **Frontend: Shadow panel** with dedicated xterm.js terminal
  - "SHADOW MODE" badge with amber accent theme
  - 👁 Shadow button on active session cards (admin/auditor only)
  - Connection status indicator (connecting/live/closed/error)
  - Fully read-only — input is silently discarded

### Backend Changes
- `models.h`: Added `sshUsername`, `sshPassword` to `Resource` struct
- `app_context.h/cc`: Shadow connections map, DB migration for SSH credential columns
- `routes.cc`: Stats routes, credential retrieval endpoint, SSH cred handling in resource CRUD
- `ssh.cc`: Shadow broadcast in reader thread, `/api/ws/shadow` WebSocket route
- `utils.h`: `resource_to_json()` includes `sshUsername`, `hasCredentials`

### Frontend Changes
- `api.js`: `fetchStats()`, `fetchResourceCredentials()` functions
- `App.jsx`: Stats dashboard, animated player, audit filters, shadow panel, vault UI
- `styles.css`: Stats grid, shadow panel styles, shadow button accent

## v0.2.0 - 2026-02-27
### Security: Password Hashing (SHA-256 + salt)
- **New: All passwords are now hashed** using iterated SHA-256 with random 128-bit salt (10000 iterations)
  - Format: `sha256:10000:<salt>:<hash>` — no external crypto library needed
  - Legacy plaintext passwords are auto-migrated on first login
  - New `crypto.h` header with SHA-256, salt generation, hash/verify functions
- **User creation and update** now hash passwords before storage
- **Admin password update** hashes the new password

### Security: Token Expiration & Server-Side Logout
- **Tokens now expire after 1 hour** (configurable `token_ttl_seconds`)
  - `expiresAt` field returned at login, checked on every API call
  - Expired tokens are automatically pruned on login
  - Frontend auto-logout timer triggers when token expires
- **New: Server-side logout endpoint** `POST /api/auth/logout`
  - Invalidates the token server-side (removes from auth_sessions map)
  - Frontend calls server logout before clearing localStorage
  - Audit event `auth.logout` recorded

### Security: Login Audit Trail
- **Login success** creates audit event `auth.login.success` with userId and username
- **Login failure** creates audit event `auth.login.failure` with reason and attempted username
- **2FA failure** creates audit event `auth.login.2fa_failure`
- **Logout** creates audit event `auth.logout`
- **Password change** creates audit event `user.password.change`

### Security: Password Policy Validation
- **Minimum 8 characters**, at least 1 uppercase, 1 lowercase, 1 digit
- Applied on: user creation, user update, password change
- Clear error messages returned to frontend

### Feature: Change Password
- **New: `POST /api/auth/change-password`** endpoint
  - Requires current password verification
  - Validates new password against policy
  - Hashes and stores the new password
  - Audit trail recorded
- **Frontend: "Change password" button** in main console navigation
  - Modal dialog with current/new/confirm password fields
  - Real-time validation feedback

### Feature: Dark Mode
- **Dark mode toggle** (🌙/☀️) on login page, main console, and admin console
- Persisted in localStorage across sessions
- Complete dark theme with Endorium-branded color palette
  - Dark surfaces (#0f172a, #1e293b), muted text (#94a3b8)
  - Adapted pills, buttons, inputs, tables, panels, modals
  - Resource tiles, session cards, audit/recording panels styled

## v0.1.0 - 2026-02-27
### Feature: Two-Factor Authentication (TOTP/2FA)
- **New: TOTP 2FA support** with built-in SHA1/HMAC-SHA1 implementation (zero external crypto dependency)
  - `/api/auth/setup-2fa` generates a TOTP secret and otpauth:// URI for QR code scanning
  - `/api/auth/verify-2fa` verifies the code and enables 2FA
  - `/api/auth/disable-2fa` disables 2FA (requires current TOTP code)
  - `/api/auth/2fa-status` returns current 2FA status
  - Login flow updated: returns `{"status":"2fa_required"}` when code is needed
  - Compatible with Google Authenticator, Authy, and all RFC 6238 TOTP apps
- **Frontend: 2FA management panel** in Admin console
  - QR code generation via API for easy authenticator setup
  - Code verification flow with 6-digit input
  - Enable/disable toggle with security confirmation
  - Login page shows TOTP input when 2FA is required
- **Database**: New `totp_enabled` and `totp_secret` columns on users table (auto-migrated)

### Feature: SSH Session Recording (Asciinema .cast format)
- **New: Automatic SSH session recording** in Asciinema v2 (.cast) format
  - All SSH sessions are automatically recorded to `recordings/` directory
  - Output events (terminal display) and input events (keystrokes) are timestamped
  - Recordings stored in `.cast` format compatible with `asciinema play` CLI tool
  - Metadata includes session ID, terminal dimensions, timestamps
- **New: Recording management API**
  - `GET /api/recordings` lists all recordings (filterable by sessionId)
  - `GET /api/recordings/<id>` returns recording metadata
  - `GET /api/recordings/<id>/cast` downloads the .cast file for replay
  - Access restricted to auditor and admin roles
- **Database**: New `session_recordings` table with metadata (duration, file size, timestamps)
- **Frontend: Recordings panel** in main console
  - List all recordings with session info, duration, and file size
  - Text-based replay viewer for .cast files
  - Per-session recording filter via session cards
  - "Recordings" button in navigation bar (auditor/admin only)

### Feature: RDP Proxy Framework (FreeRDP stub)
- **New: RDP WebSocket endpoint** `/api/ws/rdp` with authentication
  - Framework ready for FreeRDP integration
  - WebSocket-based protocol designed for bitmap streaming and input forwarding
  - Graceful 501 fallback when FreeRDP is not available at build time
  - CMake detection for FreeRDP (optional dependency)
- **New source files**: `rdp.h`, `rdp.cc`

### Backend Architecture
- Added `totp.h` — Self-contained TOTP (RFC 6238) with SHA1, HMAC-SHA1, Base32
- Added `session_recording.h/cc` — Asciinema v2 recorder
- Added `rdp.h/cc` — RDP proxy framework
- Updated `models.h` — New `SessionRecording` struct, `UserAccount` TOTP fields, `SshConnection` recorder
- Updated `app_context.h/cc` — Recording CRUD, TOTP update, recordings directory management
- Updated `ssh.cc` — Integrated session recording in SSH reader/writer
- Updated `routes.cc` — TOTP routes, recording routes, 2FA login flow
- Updated `CMakeLists.txt` — Added new source files

## v0.0.120 - 2026-02-27
### Agent v0.3.0 - Mot de passe masqué
- **Fix: Saisie du mot de passe masquée** dans l'agent interactif
  - Utilisation de `golang.org/x/term` pour désactiver l'écho terminal
  - Le mot de passe n'est plus visible lors de la saisie
  - Fallback automatique pour les entrées non-interactives (pipes, tests)

### Frontend - Corrections CSS majeures
- **Fix: Débordements de contenu** sur tous les composants
  - Ajout de `overflow: hidden` et `min-width: 0` sur les panels, cards, tiles
  - `text-overflow: ellipsis` sur les titres et infos de ressources
  - Correction des grids admin/main/hero avec `minmax(0, ...)` au lieu de tailles fixes
  - Inputs et labels contraints à 100% de largeur max
  - Resource rows avec alignement et overflow corrects
- **Fix: Responsive mobile/tablette**
  - Media queries améliorées pour écrans < 720px
  - Grids en colonnes simples sur mobile (resources, sessions, KPIs, formulaires)
  - Taille de police et padding adaptés aux petits écrans
  - `overflow-x: hidden` global pour éviter le scroll horizontal
- **Fix: WebProxy header** avec `flex-wrap` et texte tronqué

## v0.0.111 - 2025-02-27
### Architecture: Agent-Based TCP Tunnel (Systancia-style)
- **New: WebSocket TCP tunnel endpoint** (`/ws/tunnel`)
  - Backend accepts authenticated WebSocket connections and creates transparent TCP tunnels to target resources
  - Binary data forwarded bidirectionally: Agent ↔ WebSocket ↔ Target TCP
  - Authentication via `token` query parameter with resource permission checks
  - Socket timeouts: 30s send, 60s recv with EAGAIN handling for idle connections
  - Proper cleanup: upstream socket shutdown on WebSocket close, reader thread join
  - Audit events: `tunnel.open` and `tunnel.close` logged with resource and user info

- **New: EndoriumFortAgent** (Go CLI tool)
  - `login` command: authenticate with backend, obtain session token
  - `list` command: list available resources with permissions
  - `connect` command: open local TCP listener (127.0.0.1:port) and tunnel to remote resource
  - Each browser TCP connection maps to a separate WebSocket for clean multiplexing
  - Uses gorilla/websocket for reliable binary WebSocket communication
  - Cross-platform: single Go binary for Linux, Windows, macOS

- **Updated build scripts**
  - `build-all.sh` and `build-all.ps1` now include agent compilation
  - Agent build is optional (skipped if Go not available)

### Why this change
The reverse HTTP proxy approach (v0.0.56–v0.0.108) suffered from inherent limitations:
- URL/cookie/header rewriting conflicts with complex web apps (phpMyAdmin, etc.)
- AJAX responses returning HTML instead of JSON due to X-Requested-With issues
- Socket blocking and Host header mismatches
- Base tag injection regressions

The agent-based tunnel eliminates all these issues: the browser connects to 127.0.0.1 and sees the app natively, with zero rewriting needed.

## v0.0.72 - 2026-02-26
### Web Proxy: fix 401 on phpMyAdmin static assets
- **Fixed chained `401 Unauthorized` on proxied CSS/JS/images** (phpMyAdmin, similar apps)
  - Added proxy auth fallback from `Referer` query token (`?token=...`) for iframe subresource requests.
  - This covers cases where upstream app cookies and bastion auth cookie cannot coexist in a single header map implementation.
  - Result: initial page and dependent assets now load correctly through `/proxy/<id>`.

- **Fixed `POST /proxy/<id>/index.php?route=/` returning `400 Bad Request` after login submit**
  - Cause: client `Content-Length` (and related hop-by-hop headers) could be forwarded, then a second `Content-Length` was generated by proxy.
  - Fix: forwarding now filters `content-length` and `expect` (case-insensitive), while preserving valid entity headers.
  - Result: phpMyAdmin login form submission now passes through proxy correctly.

- **Fixed login loop caused by query parameter collision with app token semantics**
  - Cause: bastion auth used `token=...` in proxied redirect URLs, conflicting with applications (notably phpMyAdmin) that also use `token` for CSRF/session flow.
  - Fix: bastion now uses `ef_token=...` for redirect propagation and strips auth query params (`token`, `ef_token`) before forwarding requests to the target application.
  - Result: target app query space is preserved and login flow no longer gets polluted by bastion auth parameters.

- **Hardened auth fallback to avoid CSRF-token confusion**
  - Cause: Referer fallback could interpret an application `token` query value as a bastion token when cookies were missing.
  - Fix: Referer fallback now accepts `ef_token` first, and only accepts legacy `token` when it matches bastion token format (`tok-*`).
  - Result: phpMyAdmin `token` parameters are no longer misread as EndoriumFort auth tokens.

- **Fixed phpMyAdmin error: `Failed to set session cookie` on HTTP localhost access**
  - Cause: upstream cookie attributes were not adapted to proxied local HTTP context.
  - Fix: proxy now rewrites upstream `Set-Cookie` for web resources by removing `Secure` and forcing `Path=/proxy/<id>/`.
  - Result: browser accepts session cookies and phpMyAdmin login flow can persist session state through the bastion.

### Technical note
- Crow response headers in current setup do not preserve multiple `Set-Cookie` values under the same key in a straightforward way.
- Bastion now authenticates subresources reliably without depending only on cookie persistence.

## v0.0.67 - 2026-02-26
### Web Proxy: phpMyAdmin / iframe compatibility fixes
- **Fixed iframe blocking for proxied web apps**
  - Proxy now strips upstream `X-Frame-Options` and `Content-Security-Policy` headers that prevent embedding in the bastion iframe.
  - Resolves errors like: `Refused to display ... in a frame because it set 'X-Frame-Options' to 'deny'`.

- **Fixed binary/garbled output when opening via bastion**
  - Proxy now forces `Accept-Encoding: identity` upstream and no longer forwards client `Accept-Encoding`.
  - Prevents compressed payloads from being returned without proper decoding, which caused unreadable characters.

- **Improved proxy cookie behavior on local HTTP dev setup**
  - Removed `Secure` flag from `endoriumfort_token` cookie for the `/proxy/X/` path in HTTP local runs.
  - Allows browser to persist/send cookie correctly on `http://localhost:8080` during development.

## v0.0.61+ - 2026-02-16
### Critical Bug Fix: POST 400 Bad Request Response Handling
- **Fixed critical bug causing HTTP 400 on POST requests through proxy**
  - Issue: POST requests were returning `HTTP 400 Bad Request` instead of proper OpenWRT responses
  - Root cause: Orphaned code at end of `http_proxy_request()` was unconditionally overwriting response body with empty dechunked string
  - Solution: Removed duplicate response body assignment and properly scoped Content-Length update inside dechunk success block
  - Impact: POST requests now return correct HTTP status codes (403, 401, etc.) instead of generic 400
  - Both GET and POST now work identically through the proxy

- **Improved chunked encoding response handling**
  - Added dechunk_success flag to track dechunking status
  - Better error handling with try/catch for hex parsing
  - Only applies dechunked output if both succeeded AND produced non-empty content
  - Maintains fallback to original body if dechunking fails
  - Properly updates Content-Length header after dechunking

- **Fixed JSON URL rewriting for escaped paths** (v0.0.60)
  - Detects and rewrites escaped forward slashes in JavaScript/JSON: `\"\/path`
  - Converts to: `\"\/proxy\/X\/path` for proper proxy routing
  - Prevents double-proxification while maintaining full URL rewriting

## v0.0.56 - 2026-02-15
### Web Proxy Cookie-Based Authentication & HTML Path Rewriting
- **Implemented cookie-based authentication for web proxy** to eliminate token injection in every URL
  - Tokens now stored in `endoriumfort_token` cookie automatically sent with all requests
  - Cookie path set to `/proxy/X/` for per-resource isolation
  - Token extraction fallback chain: Authorization Bearer → query param → Cookie header
  - `Set-Cookie` header returned in responses to establish authentication state
  
- **Fixed HTML path rewriting for static resources**
  - Backend now properly converts absolute paths (`href="/path"`, `src="/path"`) to proxified paths (`/proxy/X/path`)
  - Base tag injection: `<base href="http://localhost:8080/proxy/X/">` enables relative URL resolution
  - Handles 7 URL token patterns: `href="/`, `src="/`, `action="/`, `url(/`
  - Skips already-proxified URLs and external absolute URLs

- **Frontend iframe optimization**
  - Changed iframe source from relative path to absolute backend URL (`http://localhost:8080/proxy/X?token=...`)
  - Ensures iframe properly loads from backend instead of frontend dev server
  - Token initially specified in URL, then cookie preserves auth for subsequent requests

- **Redirect token preservation**
  - Server-side redirects now append token to Location URLs
  - Ensures `Set-Cookie` is sent before redirect is followed
  - Prevents 401 errors on redirect chain processing

- **Testing**
  - Created comprehensive test suite validating all fixes
  - 8 test cases covering: backend availability, auth, resources, proxy with cookies, path rewriting, base tag, redirects, static URL rewriting
  - All tests passing (v0.0.56)

## v0.0.30 - 2026-02-15
- Ajout de `allow-modals` au sandbox de l'iframe pour autoriser les popups d'authentification HTTP
- Ajout d'un bouton "↗ Nouvel onglet" pour ouvrir les ressources web hors iframe (contourne les restrictions sandbox)
- Solution pour les interfaces nécessitant une authentification HTTP Basic interactive

## v0.0.27 - 2026-02-15
- Proxy transmet maintenant le header Authorization du navigateur vers le serveur cible
- Permet l'authentification HTTP Basic manuelle via popup du navigateur
- Les credentials peuvent être entrés soit :
  - Pré-configurés dans la ressource (httpUsername/httpPassword)
  - Manuellement via le popup du navigateur (nouveau)
- Le proxy distingue intelligemment entre le token Bearer EndoriumFort et l'auth Basic de l'utilisateur

## v0.0.24 - 2026-02-15
- Added HTTP Basic Authentication support for web proxy resources
- Resources can now have optional `httpUsername` and `httpPassword` fields
- Frontend form conditionally shows auth fields for HTTP/HTTPS resources  
- Proxy automatically adds `Authorization: Basic` header when credentials are configured
- Fixed 401 Unauthorized errors when accessing web interfaces that require authentication (e.g., LuCI)

## 2026-02-13
- Major UI refresh for the WebBastion dashboard with session management, access control, audit timeline, alerts, integrations, and personalization panels.
- Visual theme refresh to align with bastion console look-and-feel.
- Simplified UI to core session management and live SSH console, aligned to Endorium colors.
- Added login screen, admin console, and resource tiles for Systancia-style access flows.
- Added admin-managed users with default admin/admin login and resource thumbnails.
- Added a Web SSH console MVP using libssh2 with websocket streaming, plus session port support and SQLite persistence updates.
