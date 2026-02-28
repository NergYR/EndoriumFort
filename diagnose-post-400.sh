#!/bin/bash

# Diagnostic script to trace the POST 400 error in the proxy

echo "=== EndoriumFort POST 400 Diagnosis ==="
echo ""

# Step 1: Test direct connection to OpenWRT
echo "Step 1: Direct POST to OpenWRT (should return 403)"
echo "Command: curl -i -X POST http://192.168.0.31/cgi-bin/luci/"
curl -s -i -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "luci_username=root&luci_password=test" \
  "http://192.168.0.31/cgi-bin/luci/" 2>&1 | head -20
echo ""

# Step 2: Test GET through proxy (should return 403 with login form)
echo "Step 2: GET through proxy (should return 403 with login form)"  
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"admin"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

echo "Token: $TOKEN"
curl -s -i -b "endoriumfort_token=$TOKEN" \
  "http://localhost:8080/proxy/2/cgi-bin/luci/" 2>&1 | head -15
echo ""

# Step 3: Test POST through proxy (currently returns 400)
echo "Step 3: POST through proxy (currently returns 400, should be 403)"
curl -s -i -b "endoriumfort_token=$TOKEN" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "luci_username=root&luci_password=test" \
  "http://localhost:8080/proxy/2/cgi-bin/luci/" 2>&1 | head -20
echo ""

# Step 4: Test with verbose to see all headers
echo "Step 4: Verbose POST through proxy"
curl -v -b "endoriumfort_token=$TOKEN" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "luci_username=root&luci_password=test" \
  "http://localhost:8080/proxy/2/cgi-bin/luci/" 2>&1 | head -50
echo ""

echo "=== Analysis ==="
echo "If Step 1 returns 403 and Step 3 returns 400:"
echo "  → Problem is in proxy's response handling"
echo "  → Likely issue: status_code not properly preserved or dechunking failure"
echo ""
echo "If Step 2 returns HTML + 403:"
echo "  → GET through proxy works (confirms auth and cookies are ok)"
echo "  → Issue is POST-specific, not GET"
echo ""
