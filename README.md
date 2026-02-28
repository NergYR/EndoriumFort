<p align="center">
  <img src="https://img.shields.io/badge/version-0.3.1-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/license-Source--Available-orange?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/backend-C%2B%2B%2017-00599C?style=flat-square&logo=cplusplus" alt="C++">
  <img src="https://img.shields.io/badge/frontend-React%2018-61DAFB?style=flat-square&logo=react" alt="React">
  <img src="https://img.shields.io/badge/agent-Go%201.24-00ADD8?style=flat-square&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square" alt="Platform">
</p>

# 🏰 EndoriumFort

**EndoriumFort** is an open-source **Privileged Access Management (PAM)** bastion system designed to secure, monitor, and audit remote access to your infrastructure. Inspired by [Wallix](https://www.wallix.com/), [Systancia Gate](https://www.systancia.com/), [Teleport](https://goteleport.com/), and [Apache Guacamole](https://guacamole.apache.org/).

> **One gateway. Every protocol. Full audit trail.**

---

## ✨ Highlights

| Feature | Description |
|---------|-------------|
| 🔐 **Credential Vault** | Store SSH credentials securely — auto-injected on connection |
| 🖥️ **Web SSH Terminal** | Full xterm.js terminal in the browser via WebSocket |
| 🌐 **HTTP/HTTPS Proxy** | Transparent web proxy with cookie-based auth |
| 🚇 **Agent Tunnel** | Systancia-style local agent for zero-rewrite TCP tunneling |
| 👁️ **Session Shadowing** | Real-time read-only observation of active sessions |
| 🎬 **Session Recording** | Asciinema v2 format with animated in-browser replay |
| 🔑 **2FA / TOTP** | RFC 6238 two-factor authentication with QR setup |
| 🛡️ **RBAC** | Role-based access control (admin, operator, auditor) |
| 📊 **Live Dashboard** | Real-time KPI stats, session monitoring, security alerts |
| 🌙 **Dark Mode** | Full dark theme with localStorage persistence |

---

## 📐 Architecture

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

## 🗂️ Project Structure

```
EndoriumFort/
├── backend/            # C++17 API server (Crow framework)
│   ├── src/            #   main.cc, routes, SSH, tunnel, proxy, RDP
│   ├── CMakeLists.txt  #   CMake build with FetchContent (Asio, Crow)
│   └── VERSION         #   Backend version (0.0.137)
├── frontend/           # React 18 + Vite 7 SPA
│   ├── src/            #   App.jsx, styles.css, api.js, WebProxyViewer
│   ├── package.json    #   Dependencies (xterm.js, React)
│   └── VERSION         #   Frontend version (0.1.4)
├── agent/              # Go CLI tunnel agent
│   ├── main.go         #   Login, list, connect commands
│   ├── go.mod          #   gorilla/websocket
│   └── VERSION         #   Agent version (0.3.3)
├── build-all.sh        # Linux/macOS build script (smart versioning)
├── build-all.ps1       # Windows build script (PowerShell)
├── run-dev.sh          # Dev launcher (backend + frontend)
├── VERSION             # Global version (0.3.1)
├── CHANGELOG.md        # Version history
└── LICENSE             # Source-Available License
```

---

## 🚀 Quick Start

### Prerequisites

| Dependency | Required for |
|------------|-------------|
| **CMake** ≥ 3.16 | Backend build |
| **g++** / **clang++** (C++17) | Backend compilation |
| **SQLite3** (dev headers) | Database |
| **libssh2** (dev headers) | SSH terminal support |
| **Node.js** ≥ 18 | Frontend build |
| **Go** ≥ 1.24 | Agent build |

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

## 🖥️ Usage

### Web Dashboard

1. Login at `http://localhost:5173`
2. **Dashboard** — View live KPI stats, active sessions, and security alerts
3. **Resources** — Click a resource tile to connect (SSH terminal, web proxy, or agent tunnel)
4. **Sessions** — Monitor, shadow (👁), or terminate active sessions
5. **Recordings** — Replay past SSH sessions with the animated Asciinema player
6. **Audit** — Search and filter all security events
7. **Admin** — Manage users, resources, permissions, and credentials

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

# Browse http://127.0.0.1:8888 — traffic tunneled through bastion
```

Or simply **click a resource tile** with the 🚀 agent protocol — the frontend generates the command automatically with a random port.

---

## 🔒 Security Features

| Feature | Details |
|---------|---------|
| **Password Hashing** | SHA-256 with random 128-bit salt, 10,000 iterations |
| **Token Expiration** | Bearer tokens expire after 1 hour, server-side invalidation |
| **2FA / TOTP** | RFC 6238, QR code setup, compatible with Google Authenticator |
| **RBAC** | 3 roles — admin (full), operator (sessions), auditor (read-only + shadow) |
| **Credential Vault** | SSH passwords stored in DB, never exposed in standard API |
| **Session Recording** | All SSH I/O recorded in Asciinema v2 format |
| **Audit Trail** | Every action logged to JSONL — login, logout, connect, shadow, proxy |
| **Cookie Auth** | HttpOnly cookies for web proxy, no tokens in URLs |

---

## 📡 API Reference

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
| `POST` | `/api/sessions` | Create new session |
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

## 🏗️ Build System

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

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | C++17, [Crow](https://crowcpp.org/) 1.2, SQLite3, libssh2, Asio |
| **Frontend** | React 18, Vite 7, [xterm.js](https://xtermjs.org/) v6 |
| **Agent** | Go 1.24, [gorilla/websocket](https://github.com/gorilla/websocket) |
| **Build** | CMake 3.16+, npm, Go toolchain |
| **Database** | SQLite3 (file-based, zero config) |
| **Protocols** | SSH, HTTP/HTTPS, RDP (FreeRDP), VNC (planned), TCP tunnel |

---

## 🗺️ Roadmap

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
- [ ] Docker deployment
- [ ] Cluster / HA mode

---

## 📄 License

This project is released under the **EndoriumFort Source-Available License v1.0**.

**You are free to:**
- ✅ Use the software for personal, educational, or commercial purposes
- ✅ Redistribute verbatim copies with attribution

**You must:**
- 📎 **Cite this repository** in any use: [github.com/NergYR/EndoriumFort](https://github.com/NergYR/EndoriumFort)

**You may not:**
- ❌ Modify, alter, or create derivative works
- ❌ Sublicense or relicense under different terms

See [LICENSE](LICENSE) for full terms.

---

## 🤝 Contributing

Contributions via pull requests are welcome! Since the license does not allow derivative works, contributions must be submitted back to the original repository.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 👤 Author

**NergYR** — [github.com/NergYR](https://github.com/NergYR)

---

<p align="center">
  <strong>EndoriumFort</strong> — Secure your infrastructure, audit everything.
</p>
