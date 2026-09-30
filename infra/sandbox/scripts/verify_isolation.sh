#!/usr/bin/env bash
# verify_isolation.sh — Verify sandbox air-gapping and fail-closed isolation.
#
# Returns 0 if external WAN access is blocked (PASSED isolation).
# Returns 1 if any external WAN access succeeds (FAILED isolation / leak detected).

set -euo pipefail

echo "======================================================"
echo " EvidenceGraphAI Sandbox Isolation Verification"
echo "======================================================"

EXIT_CODE=0

# Test 1: DNS Resolution to external domain
echo -n "[*] Testing external DNS resolution (google.com)... "
if host -W 2 google.com >/dev/null 2>&1 || nslookup -timeout=2 google.com >/dev/null 2>&1 || ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
    echo "FAILED! External connectivity detected."
    EXIT_CODE=1
else
    echo "PASSED (Blocked as expected)"
fi

# Test 2: Direct TCP connect to public IP
echo -n "[*] Testing direct external TCP egress (1.1.1.1:53)... "
if nc -z -w 2 1.1.1.1 53 >/dev/null 2>&1 || curl -s --connect-timeout 2 http://1.1.1.1 >/dev/null 2>&1; then
    echo "FAILED! Outbound TCP traffic allowed."
    EXIT_CODE=1
else
    echo "PASSED (Blocked as expected)"
fi

# Test 3: HTTP/HTTPS request to external endpoint
echo -n "[*] Testing HTTP outbound egress (http://example.com)... "
if curl -s --connect-timeout 2 http://example.com >/dev/null 2>&1; then
    echo "FAILED! Outbound HTTP traffic allowed."
    EXIT_CODE=1
else
    echo "PASSED (Blocked as expected)"
fi

echo "------------------------------------------------------"
if [ "$EXIT_CODE" -eq 0 ]; then
    echo "[+] ISOLATION VERIFIED: Sandbox network is completely air-gapped (internal: true)."
    exit 0
else
    echo "[-] ISOLATION BREACH: External traffic leaked outside the sandbox container!"
    exit 1
fi
