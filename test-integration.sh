#!/bin/bash

# EndoriumFort Integration Test Suite v0.0.14
# Tests all major features including the new proxy functionality

set -e

echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║          🧪 EndoriumFort Integration Test Suite v0.0.14          ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0

# Helper functions
test_passed() {
    echo -e "${GREEN}✅ $1${NC}"
    ((PASS++))
}

test_failed() {
    echo -e "${RED}❌ $1${NC}"
    ((FAIL++))
}

test_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Check backend running
echo "📊 Pre-flight Checks"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if curl -s http://localhost:8080/api/health > /dev/null 2>&1; then
    test_passed "Backend responding on :8080"
else
    test_failed "Backend not responding on :8080"
    echo "Start with: cd backend/build && ./endoriumfort_backend"
    exit 1
fi

# Test 1: Auth - Login
echo ""
echo "🔑 Authentication Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

LOGIN_RESPONSE=$(curl -s http://localhost:8080/api/auth/login \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"admin"}')

TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -n "$TOKEN" ]; then
    test_passed "Login with admin/admin returned token: ${TOKEN:0:10}..."
else
    test_failed "Login failed - no token returned"
    exit 1
fi

# Test 2: Resources
echo ""
echo "📦 Resource Management Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

RESOURCES=$(curl -s http://localhost:8080/api/resources \
  -H "Authorization: Bearer $TOKEN")

if echo "$RESOURCES" | grep -q '"items"'; then
    test_passed "GET /api/resources returned items array"
else
    test_failed "GET /api/resources did not return valid response"
fi

# Check for test resource
if echo "$RESOURCES" | grep -q 'httpbin.org'; then
    test_passed "Found httpbin.org test resource"
    RESOURCE_ID=1
else
    test_warning "Test resource (httpbin.org) not found - creating it"
    
    CREATE_RESP=$(curl -s http://localhost:8080/api/resources \
      -X POST \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"name":"Test Web","target":"httpbin.org","protocol":"http","port":80}')
    
    if echo "$CREATE_RESP" | grep -q '"id"'; then
        test_passed "Created test resource (httpbin.org)"
        RESOURCE_ID=$(echo "$CREATE_RESP" | grep -o '"id":[0-9]*' | cut -d':' -f2)
    else
        test_failed "Failed to create test resource"
    fi
fi

# Test 3: HTTP Proxy - GET
echo ""
echo "🔌 HTTP Proxy Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

PROXY_GET=$(curl -s http://localhost:8080/proxy/${RESOURCE_ID}/get \
  -H "Authorization: Bearer $TOKEN" -w "\n%{http_code}")

HTTP_CODE=$(echo "$PROXY_GET" | tail -1)

if [ "$HTTP_CODE" = "200" ]; then
    test_passed "GET /proxy/$RESOURCE_ID/get returned HTTP 200"
else
    test_failed "GET /proxy/$RESOURCE_ID/get returned HTTP $HTTP_CODE"
fi

if echo "$PROXY_GET" | head -n -1 | grep -q '"args":'; then
    test_passed "Proxy response contains expected JSON from target"
else
    test_warning "Proxy response structure unexpected"
fi

# Test 4: HTTP Proxy - POST
echo ""
PROXY_POST=$(curl -s -X POST http://localhost:8080/proxy/${RESOURCE_ID}/post \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"test":"data"}' -w "\n%{http_code}")

HTTP_CODE=$(echo "$PROXY_POST" | tail -1)

if [ "$HTTP_CODE" = "200" ]; then
    test_passed "POST /proxy/$RESOURCE_ID/post returned HTTP 200"
else
    test_failed "POST /proxy/$RESOURCE_ID/post returned HTTP $HTTP_CODE"
fi

# Test 5: HTTP Proxy - Headers
echo ""
PROXY_HEADERS=$(curl -s http://localhost:8080/proxy/${RESOURCE_ID}/headers \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Custom-Test: testvalue123" | grep -o '"X-Custom-Test":"[^"]*"' || true)

if [ -n "$PROXY_HEADERS" ]; then
    test_passed "Custom headers forwarded through proxy"
else
    test_warning "Custom headers may not have been forwarded (this is optional)"
fi

# Test 6: Audit Logging
echo ""
echo "📝 Audit Logging Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "/home/energetiq/EndoriumFort/backend/audit-log.jsonl" ]; then
    test_passed "Audit log file exists"
    
    AUDIT_COUNT=$(wc -l < /home/energetiq/EndoriumFort/backend/audit-log.jsonl)
    test_passed "Audit log has $AUDIT_COUNT entries"
    
    if grep -q "web.proxy_access\|auth.login" /home/energetiq/EndoriumFort/backend/audit-log.jsonl; then
        test_passed "Audit events found in log"
    else
        test_warning "Expected audit events not found (may be empty on first run)"
    fi
else
    test_failed "Audit log file not found"
fi

# Test 7: Version
echo ""
echo "📌 Version Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

VERSION=$(curl -s http://localhost:8080/api/health | grep -o '"version":"[^"]*"' | cut -d'"' -f4)

if [ -n "$VERSION" ]; then
    test_passed "Backend version: $VERSION"
    
    if [[ "$VERSION" =~ ^0\.0\. ]]; then
        test_passed "Version format is valid (0.0.X pattern)"
    fi
else
    test_failed "Could not retrieve version"
fi

# Test 8: Permissions
echo ""
echo "👥 Permission Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Get admin user ID
USERS=$(curl -s http://localhost:8080/api/users \
  -H "Authorization: Bearer $TOKEN")

ADMIN_ID=$(echo "$USERS" | grep -o '"id":[0-9]*' | head -1 | cut -d':' -f2)

if [ -n "$ADMIN_ID" ]; then
    PERMS=$(curl -s http://localhost:8080/api/users/$ADMIN_ID/resources \
      -H "Authorization: Bearer $TOKEN")
    
    if echo "$PERMS" | grep -q '"[0-9]*"'; then
        test_passed "Admin has permissions to resources"
    else
        test_warning "Permission structure may be empty (new installation)"
    fi
else
    test_warning "Could not retrieve admin user ID"
fi

# Summary
echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                          📊 TEST RESULTS                          ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo -e "Passed: ${GREEN}$PASS${NC}"
echo -e "Failed: ${RED}$FAIL${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✅ All tests PASSED!${NC}"
    echo ""
    echo "🚀 System is ready for production"
    echo ""
    exit 0
else
    echo -e "${RED}❌ Some tests FAILED${NC}"
    echo ""
    echo "Please review errors above and fix issues"
    echo ""
    exit 1
fi
