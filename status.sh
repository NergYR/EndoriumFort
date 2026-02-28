#!/bin/bash

# Quick status checker for EndoriumFort
# Shows current version, running services, and available endpoints

echo ""
echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║                   🔐 EndoriumFort Status v0.0.56                   ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

# Check backend
echo "📊 Backend Status"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if pgrep -f "endoriumfort_backend" > /dev/null; then
    echo "✅ Running on http://localhost:8080"
    curl -s http://localhost:8080/api/health | head -1
else
    echo "❌ Not running"
fi
echo ""

# Check frontend
echo "🎨 Frontend Status"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if pgrep -f "vite" > /dev/null; then
    echo "✅ Dev server running on http://localhost:5173"
else
    echo "⚠️  Dev server not running (use: npm run dev in frontend/)"
fi
echo ""

# Features
echo "✨ Implemented Features"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Authentication (Token-based Bearer + Cookies)"
echo "✅ User Management (Admin console)"
echo "✅ SSH Sessions (libssh2 WebSocket console)"
echo "✅ Resource Management (SSH + HTTP)"
echo "✅ Permission Control (User-Resource grants)"
echo "✅ Audit Logging (JSONL format)"
echo "✨ HTTP/HTTPS Proxy (Cookie-based auth v0.0.56)"
echo "✨ Web Resource Access (HTML path rewriting)"
echo "✨ Smart Resource Routing (Transparent authentication)"
echo ""

# Quick API tests
echo "🧪 Quick API Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

TOKEN=$(curl -s http://localhost:8080/api/auth/login -X POST \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"admin"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4 2>/dev/null)

if [ -n "$TOKEN" ]; then
    echo "✅ Auth: Login successful (token: ${TOKEN:0:10}...)"
    
    RESOURCE_COUNT=$(curl -s http://localhost:8080/api/resources \
      -H "Authorization: Bearer $TOKEN" 2>/dev/null | grep -o '"id":' | wc -l)
    echo "✅ Resources: $RESOURCE_COUNT available"
    
    PROXY_TEST=$(curl -s -o /dev/null -w "%{http_code}" -b "endoriumfort_token=$TOKEN" http://localhost:8080/proxy/2/cgi-bin/luci/ 2>/dev/null)
    if [ "$PROXY_TEST" = "200" ] || [ "$PROXY_TEST" = "401" ]; then
        echo "✅ Proxy: Working (HTTP $PROXY_TEST)"
    else
        echo "⚠️  Proxy: HTTP $PROXY_TEST (might be offline)"
    fi
else
    echo "❌ Auth: Failed to get token"
fi
echo ""

# Files
echo "📁 Key Files"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Backend:        backend/src/main.cc (2973 lines - v0.0.56)"
echo "  ├─ Cookie extraction & validation"
echo "  ├─ HTML path rewriting (/path → /proxy/X/path)"
echo "  └─ Base tag injection for relative URLs"
echo "Frontend:       frontend/src/App.jsx (1276 lines)"
echo "  ├─ WebProxyViewer.jsx (iframe + new tab button)"
echo "  └─ webproxy.css (proxy styles)"
echo "Utils:          frontend/src/api.js (232 lines)"
echo "Database:       endoriumfort.db (SQLite)"
echo "Audit Log:      backend/audit-log.jsonl"
echo "Version:        backend/VERSION (auto-increment on build)"
echo ""

# Credentials
echo "🔑 Default Credentials"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Username: admin"
echo "Password: admin"
echo ""

# Documentation
echo "📚 Documentation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "README.md                  - Main documentation"
echo "CHANGELOG.md               - Version history & v0.0.56 details"
echo "WEB_PROXY_TESTING.md       - Testing & troubleshooting guide"
echo "CHANGES_v0.0.56.md         - Detailed change summary"
echo ""

# Commands
echo "🚀 Quick Commands"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Development:"
echo "  ./run-dev.sh              - Start backend + frontend"
echo "  npm run dev               - Frontend only"
echo "  npm run build             - Build frontend"
echo "  cd backend/build && make  - Rebuild backend"
echo ""
echo "Testing:"
echo "  curl -b 'endoriumfort_token=tok-1000' http://localhost:8080/proxy/2/cgi-bin/luci/"
echo "  sh test-cookie-auth.sh     - Run full cookie auth test suite"
echo ""

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║                                                                    ║"
echo "║  💡 Start with: ./run-dev.sh                                      ║"
echo "║  💡 Then open:  http://localhost:5173 (admin/admin)              ║"
echo "║                                                                    ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""
