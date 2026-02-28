#!/bin/bash

# Diagnostic script for cookie authentication issues in EndoriumFort proxy
# Tests the complete cookie flow and identifies 401 Unauthorized problems

echo ""
echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║        🔍 EndoriumFort Cookie Authentication Diagnostic            ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test 1: Backend availability
echo -e "${BLUE}[Test 1]${NC} Backend connectivity..."
if ! timeout 2 bash -c 'cat < /dev/null > /dev/tcp/localhost/8080' 2>/dev/null; then
  echo -e "${RED}✗ FAIL${NC}: Cannot connect to localhost:8080"
  echo "  Has backend crashed? Run: ps aux | grep endoriumfort_backend"
  exit 1
fi
echo -e "${GREEN}✓ PASS${NC}: Backend listening on port 8080"
echo ""

# Test 2: Get authentication token
echo -e "${BLUE}[Test 2]${NC} Admin authentication..."
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"admin"}')
TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
  echo -e "${RED}✗ FAIL${NC}: Could not obtain token"
  echo "  Response: $TOKEN_RESPONSE"
  exit 1
fi
echo -e "${GREEN}✓ PASS${NC}: Got token: $TOKEN"
echo ""

# Test 3: First request WITH token in URL (initial iframe load)
echo -e "${BLUE}[Test 3]${NC} Initial proxied request (token in URL)..."
RESPONSE_WITH_TOKEN=$(curl -s -i -b "" \
  "http://localhost:8080/proxy/2/cgi-bin/luci/?token=$TOKEN" 2>&1)

HTTP_CODE=$(echo "$RESPONSE_WITH_TOKEN" | grep "HTTP/" | head -1 | awk '{print $2}')
SET_COOKIE=$(echo "$RESPONSE_WITH_TOKEN" | grep -i "^Set-Cookie:" | head -1)

if [ "$HTTP_CODE" = "200" ]; then
  echo -e "${GREEN}✓ PASS${NC}: Got HTTP 200 with token in URL"
else
  echo -e "${RED}✗ FAIL${NC}: Got HTTP $HTTP_CODE (expected 200)"
fi

if [ -n "$SET_COOKIE" ]; then
  echo -e "${GREEN}✓ PASS${NC}: Set-Cookie header present"
  echo "  Header: $SET_COOKIE"
else
  echo -e "${RED}✗ FAIL${NC}: No Set-Cookie header found"
  echo "  Full response headers:"
  echo "$RESPONSE_WITH_TOKEN" | head -20
fi
echo ""

# Test 4: Extract cookie from response and use it
echo -e "${BLUE}[Test 4]${NC} Cookie extraction and validation..."
COOKIE_VALUE=$(echo "$RESPONSE_WITH_TOKEN" | grep -i "^Set-Cookie:" | \
  sed 's/.*endoriumfort_token=\([^;]*\).*/\1/' | head -1)

if [ -z "$COOKIE_VALUE" ]; then
  echo -e "${RED}✗ FAIL${NC}: Could not extract cookie value from Set-Cookie"
  exit 1
fi
echo -e "${GREEN}✓ PASS${NC}: Extracted cookie: endoriumfort_token=$COOKIE_VALUE"
echo ""

# Test 5: Second request WITH extracted cookie (simulating browser behavior)
echo -e "${BLUE}[Test 5]${NC} Subsequent request using cookie (no token in URL)..."
RESPONSE_WITH_COOKIE=$(curl -s -i -b "endoriumfort_token=$COOKIE_VALUE" \
  "http://localhost:8080/proxy/2/cgi-bin/luci/" 2>&1)

HTTP_CODE_2=$(echo "$RESPONSE_WITH_COOKIE" | grep "HTTP/" | head -1 | awk '{print $2}')

if [ "$HTTP_CODE_2" = "200" ]; then
  echo -e "${GREEN}✓ PASS${NC}: Got HTTP 200 with cookie only (no URL token)"
  echo "  Authenticated request successful! ✨"
elif [ "$HTTP_CODE_2" = "401" ]; then
  echo -e "${RED}✗ FAIL${NC}: Got HTTP 401 Unauthorized"
  echo "  Issue: Cookie not being accepted by backend"
  echo ""
  echo "  Debugging info:"
  echo "  Cookie sent: Cookie: endoriumfort_token=$COOKIE_VALUE"
  echo "  Cookie value: $COOKIE_VALUE"
  echo "  Token from login: $TOKEN"
  echo ""
  echo "  Possible causes:"
  echo "  1. Cookie value corrupted during extraction"
  echo "  2. Cookie not properly parsed on backend"
  echo "  3. Cookie domain/path mismatch"
else
  echo -e "${YELLOW}⚠${NC} Got HTTP $HTTP_CODE_2 (unexpected)"
fi
echo ""

# Test 6: Third request with Bearer token (fallback method)
echo -e "${BLUE}[Test 6]${NC} Bearer token fallback (no cookie, token in header)..."
RESPONSE_WITH_BEARER=$(curl -s -i -b "" -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/proxy/2/cgi-bin/luci/" 2>&1)

HTTP_CODE_3=$(echo "$RESPONSE_WITH_BEARER" | grep "HTTP/" | head -1 | awk '{print $2}')

if [ "$HTTP_CODE_3" = "200" ]; then
  echo -e "${GREEN}✓ PASS${NC}: Got HTTP 200 with Bearer token"
  echo "  Fallback authentication working!"
else
  echo -e "${RED}✗ FAIL${NC}: Got HTTP $HTTP_CODE_3 (expected 200)"
fi
echo ""

# Test 7: Check if paths are being rewritten
echo -e "${BLUE}[Test 7]${NC} HTML path rewriting verification..."
BODY=$(echo "$RESPONSE_WITH_TOKEN" | sed '1,/^$/d')

# Count rewritten paths
HREF_PROXY=$(echo "$BODY" | grep -o 'href="/proxy/' | wc -l)
SRC_PROXY=$(echo "$BODY" | grep -o 'src="/proxy/' | wc -l)
BASE_TAG=$(echo "$BODY" | grep -o '<base href="http://localhost:8080/proxy/[^"]*"' | wc -l)

if [ "$HREF_PROXY" -gt 0 ] || [ "$SRC_PROXY" -gt 0 ]; then
  echo -e "${GREEN}✓ PASS${NC}: HTML paths properly rewritten"
  echo "  - href with /proxy/: $HREF_PROXY"
  echo "  - src with /proxy/: $SRC_PROXY"
fi

if [ "$BASE_TAG" -gt 0 ]; then
  echo -e "${GREEN}✓ PASS${NC}: Base tag injected for relative URLs"
else
  echo -e "${YELLOW}⚠${NC} No base tag found (relative URLs may not resolve)"
fi
echo ""

# Test 8: Simulate iframe behavior (check request headers)
echo -e "${BLUE}[Test 8]${NC} Testing iframe-specific behavior..."
echo "  Simulating: iframe sends requests with credentials=include"

# This tests if the cookie would be sent by an iframe with credentials
IFRAME_RESPONSE=$(curl -s -i -b "endoriumfort_token=$COOKIE_VALUE" \
  -H "Origin: http://localhost" \
  -H "Referer: http://localhost:5173/" \
  "http://localhost:8080/proxy/2/cgi-bin/luci/admin/" 2>&1)

HTTP_CODE_IFRAME=$(echo "$IFRAME_RESPONSE" | grep "HTTP/" | head -1 | awk '{print $2}')

if [ "$HTTP_CODE_IFRAME" = "200" ] || [ "$HTTP_CODE_IFRAME" = "301" ] || [ "$HTTP_CODE_IFRAME" = "302" ]; then
  echo -e "${GREEN}✓ PASS${NC}: Iframe requests accepted (HTTP $HTTP_CODE_IFRAME)"
elif [ "$HTTP_CODE_IFRAME" = "401" ]; then
  echo -e "${RED}✗ FAIL${NC}: HTTP 401 - Cookie not working for iframe requests"
  echo ""
  echo "  This is the issue! Iframe requests are getting 401."
  echo "  Possible solutions:"
  echo "  1. Check cookie domain (may need to set Domain explicitly)"
  echo "  2. Check cookie SameSite setting (may be blocking cross-origin)"
  echo "  3. Verify iframe includes credentials (credentials=include)"
  echo ""
else
  echo -e "${YELLOW}⚠${NC} Got HTTP $HTTP_CODE_IFRAME"
fi
echo ""

# Summary
echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║                           📋 Summary                               ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

if [ "$HTTP_CODE" = "200" ] && [ "$HTTP_CODE_2" = "200" ]; then
  echo -e "${GREEN}✅ Cookie authentication is working correctly!${NC}"
  echo ""
  echo "If you're still seeing 401 in the browser iframe, check:"
  echo "  1. Browser DevTools → Application → Cookies"
  echo "     Look for: endoriumfort_token=..."
  echo "  2. Browser DevTools → Network tab"
  echo "     Check Cookie header in requests to /proxy/2/..."
  echo "  3. iFrame credentials setting in WebProxyViewer.jsx"
  echo "     Should have: credentials='include'"
  echo ""
elif [ "$HTTP_CODE_2" = "401" ]; then
  echo -e "${RED}❌ Cookie authentication failed!${NC}"
  echo ""
  echo "The server is not accepting the cookie. Possible causes:"
  echo "  1. Backend /find_auth() function not extracting cookie correctly"
  echo "  2. Cookie value isn't matching between Set-Cookie and Cookie header"
  echo "  3. Cookie path mismatch (Set-Cookie Path=/proxy/2/ may be wrong)"
  echo ""
  echo "Debug steps:"
  echo "  1. Check backend logs for 'find_auth' or cookie parsing errors"
  echo "  2. Verify cookie extraction regex: endoriumfort_token=..."
  echo "  3. Test with Bearer token instead: works? Then it's backend parsing"
  echo ""
else
  echo -e "${YELLOW}⚠ Mixed results - see individual test outputs above${NC}"
fi

echo ""
echo "Helpful commands:"
echo "  tail -f /tmp/backend.log          # Show backend logs"
echo "  curl -v -b 'endoriumfort_token=$TOKEN' http://localhost:8080/proxy/2/cgi-bin/luci/ | head -30"
echo "  curl -i http://localhost:8080/api/health          # Check backend"
echo ""
