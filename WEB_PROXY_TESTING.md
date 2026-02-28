# Web Proxy Cookie-Based Authentication Testing Guide

## Overview (v0.0.56)

EndoriumFort now provides **transparent cookie-based authentication** for HTTP/HTTPS web resources. This guide walks you through testing the complete proxy flow with the OpenWRT LuCI interface.

## Quick Start Testing

### 1. Verify Backend is Running

```bash
# Check backend on port 8080
curl http://localhost:8080/api/health

# Should return 200 OK with health status
```

### 2. Login and Get Token

```bash
# Get an authentication token
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"admin"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

echo "Token: $TOKEN"
# Example output: Token: tok-1001
```

### 3. Create Web Resource (if needed)

```bash
# Create a resource for OpenWRT/LuCI (IP: 192.168.0.31)
curl -s -X POST http://localhost:8080/api/resources \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "OpenWRT LuCI",
    "target": "192.168.0.31",
    "protocol": "http",
    "port": 80,
    "description": "OpenWRT Web Interface"
  }' | grep -o '"id":[0-9]*'

# Example output: "id":2
```

### 4. Test Proxy with Cookie Authentication

```bash
# Request proxy with cookie-based auth
curl -s -b "endoriumfort_token=$TOKEN" \
  http://localhost:8080/proxy/2/cgi-bin/luci/ | head -100

# Should receive HTML content (<!DOCTYPE html>)
```

## Expected Test Results

### Cookie Authentication
```
✓ Backend accepts endoriumfort_token cookie
✓ Token extracted and validated from Cookie header
✓ 200 OK response with HTML content
✗ 401 Unauthorized if cookie missing or invalid
```

### HTML Path Rewriting
```
✓ Absolute paths rewritten: <link href="/proxy/2/luci-static/...">
✓ Base tag injected: <base href="http://localhost:8080/proxy/2/">
✓ Script src rewritten: <script src="/proxy/2/cgi-bin/luci/...">
✓ All relative URLs resolve via base tag
```

### Frontend Iframe Access

1. Open `http://localhost:5173` in browser
2. Login with `admin:admin`
3. Click on "OpenWRT LuCI" resource (or any HTTP resource)
4. **Expected**: Full LuCI interface displays in iframe
   - No 401 errors
   - CSS/JS resources load successfully
   - Page fully functional

### New Tab Access

1. In the proxy viewer, click **"↗ Nouvel onglet"** button
2. **Expected**: New tab opens with same resource
   - Cookie automatically sent with new requests
   - Full authentication state preserved
   - No need to re-login

## Example Test Commands

### Full Validation Suite

```bash
#!/bin/bash

TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"admin"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

echo "Testing Cookie Auth..."
RESPONSE=$(curl -s -b "endoriumfort_token=$TOKEN" http://localhost:8080/proxy/2/cgi-bin/luci/)

# Check 1: HTML received
if echo "$RESPONSE" | grep -q "<!DOCTYPE html"; then
  echo "✓ HTML content received"
fi

# Check 2: Base tag present
if echo "$RESPONSE" | grep -q '<base href="http://localhost:8080/proxy/2/">'; then
  echo "✓ Base tag correctly injected"
fi

# Check 3: Paths rewritten
if echo "$RESPONSE" | grep -q 'href="/proxy/2/'; then
  echo "✓ href paths rewritten"
fi

if echo "$RESPONSE" | grep -q 'src="/proxy/2/'; then
  echo "✓ src paths rewritten"
fi

# Check 4: No absolute references to /luci-static/ without proxy prefix
if ! echo "$RESPONSE" | grep -q 'href="/luci-static/'; then
  echo "✓ No unproxified luci-static references in href"
fi

echo "All tests passed!"
```

## Architecture Diagram

```
User Browser (5173)
    ↓
    [Login: admin/admin]
    ↓
    /api/auth/login → Token: tok-XXXX
    ↓
    [View Resource → iframe]
    ↓
    Frontend: http://localhost:5173
        iframe src="http://localhost:8080/proxy/2?token=tok-XXXX"
    ↓
Backend (8080) - /proxy/2/...
    ↓
    [Extract Cookie: endoriumfort_token=tok-XXXX]
    ↓
    [Look up resource 2: 192.168.0.31:80]
    ↓
    [Proxy request to OpenWRT]
    ↓
    [Rewrite HTML paths: /luci-static/ → /proxy/2/luci-static/]
    ↓
    [Inject base tag + Set-Cookie]
    ↓
Browser receives:
    - <!DOCTYPE html...
    - <base href="http://localhost:8080/proxy/2/">
    - <link href="/proxy/2/luci-static/...">
    - Set-Cookie: endoriumfort_token=tok-XXXX; Path=/proxy/2/
    ↓
[All subsequent requests include cookie automatically]
    ↓
✓ Transparent authentication, no re-login needed
```

## Troubleshooting

### 401 Unauthorized
- **Cause**: Cookie not sent or invalid
- **Fix**: Ensure `Cookie: endoriumfort_token=tok-XXXX` header is present
- **Check**: `curl -v -b "endoriumfort_token=$TOKEN" http://localhost:8080/proxy/2/...`

### 404 Resource Not Found
- **Cause**: Resource ID doesn't exist
- **Fix**: Create resource via `/api/resources` POST or check ID in `/api/web/resources`

### 403 Access Denied
- **Cause**: User lacks permission for resource
- **Fix**: Admin users have all permissions; for others, grant via `/api/users/{user_id}/resources/{resource_id}`

### Static Resources (CSS/JS) Not Loading
- **Cause**: Paths not properly rewritten or relative URLs not resolved
- **Expected signs of working**:
  - `<link href="/proxy/2/luci-static/...">` (not `/luci-static/...`)
  - `<base href="http://localhost:8080/proxy/2/">` present
  - Network tab shows resources loading from `/proxy/2/...`

### CORS or Content-Type Issues
- **Note**: Not relevant - proxy handles all traffic transparently
- **All requests** go through backend which properly translates headers

## Version History
- **v0.0.56**: Cookie-based authentication, HTML path rewriting, auth token preservation
- **v0.0.30**: Basic proxy, requires token in every URL
- **v0.0.14**: Initial web proxy implementation

## Security Considerations

1. **Cookie Scoping**: Path set to `/proxy/{resourceId}/` prevents token leakage
2. **HttpOnly Flag**: Can be set in production to prevent JavaScript access
3. **SameSite**: Lax by default, adjust based on cross-site requirements
4. **Token Expiry**: Currently no built-in expiry; consider implementing
5. **HTTPS**: Use HTTPS in production for cookie security

## Related Files

- **Backend**: [backend/src/main.cc](backend/src/main.cc) - `handle_proxy_request()`, `rewrite_html_body()`
- **Frontend**: [frontend/src/WebProxyViewer.jsx](frontend/src/WebProxyViewer.jsx) - iframe and new tab button
- **Database**: [backend/endoriumfort.db](backend/endoriumfort.db) - resources table
- **Changelog**: [CHANGELOG.md](CHANGELOG.md) - v0.0.56 section
- **README**: [README.md](README.md) - Web Proxy Features section
