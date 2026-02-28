# Changelog

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
