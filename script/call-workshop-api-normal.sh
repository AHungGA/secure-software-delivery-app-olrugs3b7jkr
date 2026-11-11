#!/usr/bin/env bash
# Trigger normal (benign) requests against the workshop API.
# Usage:
#   ./script/call-workshop-api-normal.sh
#   ./script/call-workshop-api-normal.sh http://YOUR_EC2_PUBLIC_IP
#   BASE_URL=http://54.x.x.x ./script/call-workshop-api-normal.sh

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
  echo "  1) Confirm the EC2 public IP (it changes after stop/start unless you use an Elastic IP)."
  echo "  2) In the instance security group, allow inbound TCP 80 (nginx) or 3000 from YOUR laptop's public IP."
  echo "     (Opening SSH for one IP does not open HTTP for that IP.)"
  MY_IP=$(curl -sS --max-time 5 https://checkip.amazonaws.com 2>/dev/null || echo "unknown")
  echo "  3) Your current public IP (for a /32 rule): ${MY_IP}"
  echo ""
  echo "AWS CLI example (replace REGION and GROUP_ID):"
  echo "  aws ec2 authorize-security-group-ingress --region REGION --group-id sg-xxxxxxxx \\"
  echo "    --protocol tcp --port 80 --cidr ${MY_IP}/32"
  exit 1
}

hit() {
  local name="$1"
  local path="$2"
  local code
  code=$(curl -sS -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 15 "${BASE_URL}${path}" 2>/dev/null || true)
  if [ -z "${code}" ] || [ "${code}" = "000" ]; then
    printf "  %-28s FAIL  %s\n" "${name}" "${path}"
  else
    printf "  %-28s %s  %s\n" "${name}" "${code}" "${path}"
  fi
}

preflight

echo "=== Normal API calls ==="
hit "Health" "/health"
hit "Vuln index" "/api/vuln"
hit "SQL (id=1)" "/api/vuln/sql?id=1"
hit "Misconfig" "/api/vuln/misconfig"
hit "XSS page" "/api/vuln/xss?q=hello"
hit "Ping" "/api/vuln/command/ping?host=127.0.0.1"
hit "Glob" "/api/vuln/glob?pattern=*.js&value=index.js"
hit "JWT sign" "/api/vuln/jwt/sign?sub=demo"
echo ""
echo "Done."
