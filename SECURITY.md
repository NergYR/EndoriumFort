# Security Policy — EndoriumFort

## Reporting a Vulnerability

If you discover a security vulnerability in EndoriumFort, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email the maintainer at: **[open an issue with the `security` label]**
3. Include: description, steps to reproduce, impact assessment
4. You will receive a response within 72 hours

---

## Security Audit Summary (v0.4.0)

A comprehensive security audit was performed covering the entire codebase (C++ backend, React frontend, Go agent). Below is the summary of findings and remediations.

### Findings & Remediations

| # | Vulnerability | Severity | Status | Fix |
|---|---|---|---|---|
| 01 | Default admin password `admin` | **HIGH** | ✅ Fixed | Changed to `Admin123`, warning logged at startup |
| 02 | Tokens leaked in URL query strings | **HIGH** | ⚠️ Mitigated | Proxy uses cookie-based auth; WebSocket tokens still in query (WebSocket spec limitation) |
| 03 | Tokens logged in stderr | **HIGH** | ✅ Fixed | Tokens masked to first 8 chars in all logs |
| 04 | Resource credentials stored in plaintext | **HIGH** | ⚠️ Noted | Planned: AES-256 encryption for vault (v0.5.0) |
| 05 | No rate limiting on login | **HIGH** | ✅ Fixed | 10 attempts per 5-minute window per username, `429 Too Many Requests` |
| 06 | No TLS (HTTP only) | **HIGH** | ⚠️ Noted | Crow supports TLS natively; deploy behind nginx/caddy for production |
| 07 | SSRF via proxy/tunnel (access to internal hosts) | **HIGH** | ✅ Fixed | Blocked: loopback, link-local, cloud metadata endpoints |
| 08 | SSH WebSocket no resource permission check | **HIGH** | ⚠️ Noted | Session ownership verified; resource-level check planned |
| 09 | Token in JSON response (`/api/web/resources/.../url`) | **MEDIUM** | ✅ Fixed | Token removed from response, cookie-based auth used |
| 10 | Missing RBAC on sessions/stats/web-resources | **MEDIUM** | ✅ Fixed | `GET /api/sessions` → admin/auditor/operator; `GET /api/stats` → admin/auditor; `GET /api/web/resources` → permission-filtered |
| 11 | No security headers (CSP, X-Frame-Options, etc.) | **MEDIUM** | ✅ Fixed | Added: X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy, Permissions-Policy, Cache-Control |
| 12 | JSON injection in audit logs | **MEDIUM** | ✅ Fixed | All user-controlled values passed through `json_escape()` |
| 13 | No protocol validation on resources | **MEDIUM** | ✅ Fixed | Whitelist: ssh, rdp, vnc, http, https, agent |
| 14 | No target hostname validation | **MEDIUM** | ✅ Fixed | SSRF protection blocks dangerous addresses |
| 15 | Token generated with mt19937_64 (not CSPRNG) | **MEDIUM** | ✅ Fixed | Uses `/dev/urandom` directly (64-byte tokens) |
| 16 | No token rotation on password change | **MEDIUM** | ✅ Fixed | All user tokens invalidated on password change |
| 17 | `gethostbyname()` not thread-safe | **MEDIUM** | ✅ Fixed | Replaced with `getaddrinfo()` in tunnel.cc and http_proxy.cc |
| 18 | Cookie missing `Secure` flag | **MEDIUM** | ⚠️ Noted | Add `Secure` when TLS is enabled |
| 19 | `allow-top-navigation` in iframe sandbox | **MEDIUM** | ✅ Fixed | Changed to `allow-top-navigation-by-user-activation` |
| 20 | Hardcoded `http://localhost:8080` in WebProxyViewer | **MEDIUM** | ✅ Fixed | Uses relative URLs now |
| 21 | Agent: token displayed in full on stdout | **MEDIUM** | ✅ Fixed | Masked to 12 chars, saved to `~/.endoriumfort_token` (0600) |
| 22 | Agent: password in CLI args (visible in `ps`) | **MEDIUM** | ✅ Fixed | Support for `EF_PASSWORD` env var added |
| 23 | Agent: no warning on non-TLS connection | **MEDIUM** | ✅ Fixed | Warning printed when using `http://` |
| 24 | Agent: token in CLI args | **MEDIUM** | ✅ Fixed | Support for `EF_TOKEN` env var + `~/.endoriumfort_token` file |
| 25 | No input length limits | **LOW** | ✅ Fixed | Max: name 255, target 255, description 1024 |
| 26 | `imageUrl` not validated | **LOW** | ✅ Fixed | Must start with `http` or `/` |
| 27 | SHA-256 iterated instead of argon2/bcrypt | **LOW** | ⚠️ Noted | Current: 10,000 iterations. Migration to argon2id planned |

### Legend
- ✅ **Fixed** — Vulnerability remediated in this version
- ⚠️ **Mitigated** — Partially addressed or planned for future release
- ⚠️ **Noted** — Acknowledged, requires architectural change or external tooling

---

## Security Architecture

### Authentication Flow
```
User → Password (SHA-256 × 10,000 + salt) → Token (64-byte /dev/urandom)
     → Optional TOTP 2FA verification
     → Bearer token (1h TTL, server-side invalidation)
```

### Rate Limiting
- **Login endpoint**: 10 attempts per 5-minute sliding window per username
- Exceeded → `429 Too Many Requests` + audit event `auth.login.rate_limited`
- Automatic cleanup of expired rate limit entries

### SSRF Protection
Blocked target addresses:
- `127.0.0.0/8` (loopback)
- `169.254.0.0/16` (link-local / cloud metadata)
- `0.0.0.0/8` (unspecified)
- `localhost`, `::1`
- `169.254.169.254` (AWS/GCP/Azure metadata)
- `metadata.google.internal`

### HTTP Security Headers
All responses include:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Cache-Control: no-store, no-cache, must-revalidate
Content-Security-Policy: default-src 'self'; ...
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### Token Security
- Generated from `/dev/urandom` (cryptographically secure)
- 64 hex characters + `eft_` prefix (256 bits of entropy)
- Server-side invalidation on logout and password change
- 1-hour TTL with automatic expiration
- Never logged in full (masked to first 8 chars)

### RBAC Matrix

| Route | admin | operator | auditor |
|---|---|---|---|
| Users CRUD | ✅ | ❌ | ❌ |
| Resources CRUD | ✅ | ❌ | ❌ |
| Permissions | ✅ | ❌ | ❌ |
| Sessions list | ✅ | ✅ | ✅ |
| Sessions create/terminate | ✅ | ✅ | ❌ |
| SSH terminal | ✅ | ✅ | ❌ |
| Session shadow | ✅ | ❌ | ✅ |
| Stats dashboard | ✅ | ❌ | ✅ |
| Audit logs | ✅ | ❌ | ✅ |
| Recordings | ✅ | ❌ | ✅ |
| Credentials access | ✅ | ✅ (with permission) | ❌ |

---

## Production Deployment Recommendations

1. **Enable TLS** — Use Crow's native TLS or deploy behind nginx/caddy with Let's Encrypt
2. **Change default admin password** immediately after first login
3. **Enable 2FA** for all admin accounts
4. **Use environment variables** for agent credentials (`EF_TOKEN`, `EF_PASSWORD`)
5. **Restrict network access** — Backend should not be exposed to the public internet without a reverse proxy
6. **Monitor audit logs** — Review `audit-log.jsonl` regularly for suspicious activity
7. **Backup database** — `endoriumfort.db` contains all user, resource, and session data
8. **Set file permissions** — Ensure `endoriumfort.db`, `audit-log.jsonl`, and `recordings/` are readable only by the service user

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | ✅ Security updates |
| 0.3.x   | ⚠️ Critical fixes only |
| < 0.3   | ❌ No longer supported |
