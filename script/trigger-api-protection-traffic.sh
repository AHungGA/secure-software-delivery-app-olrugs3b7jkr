#!/bin/sh
# Continuous (or one-shot) HTTP traffic with varied /api/vuln patterns for Datadog
# App and API Protection (ASM) on the instrumented Node app.
#
# Compose sets LOOP=1 for workshop-long traffic. On the host, LOOP defaults to 0 (one sweep).
# INTERVAL=90s between full sweeps when looping; PAUSE_BETWEEN=1s between requests in a sweep.
# Run on the host: BASE_URL=http://127.0.0.1:80 npm run lab:trigger-appsec   # single sweep
# Continuous on host: BASE_URL=http://127.0.0.1:80 LOOP=1 npm run lab:trigger-appsec
set -eu

BASE_URL="${BASE_URL:-http://workshop-app:3000}"
STARTUP_DELAY="${STARTUP_DELAY:-8}"
LOOP="${LOOP:-0}"
INTERVAL="${INTERVAL:-90}"
PAUSE_BETWEEN="${PAUSE_BETWEEN:-1}"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*"; }

get() {
  path="$1"
  log "GET ${path}"
  curl -sS -m 25 "${BASE_URL}${path}" >/dev/null || true
}

post_json() {
  path="$1"
  body="$2"
  log "POST ${path}"
  curl -sS -m 25 -X POST \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -d "$body" \
    "${BASE_URL}${path}" >/dev/null || true
}

p() { sleep "${PAUSE_BETWEEN}"; }

# One full sweep across many workshop routes (GET + POST), varied week-over-week payloads.
burst_full() {
  log "=== App & API Protection: full sweep -> ${BASE_URL} ==="

  # --- SQLi / command / XSS / SSRF ---
  get "/api/vuln/sql?id=1%20OR%201%3D1"; p
  post_json "/api/vuln/sql" '{"username":"admin'\'' OR '\''1'\''='\''1"}'; p
  post_json "/api/vuln/sql-search" '{"table":"users","column":"name","value":"x'\'' OR '\''1'\''='\''1"}'; p
  get "/api/vuln/command/exec?cmd=id"; p
  get "/api/vuln/command/ping?host=127.0.0.1"; p
  get "/api/vuln/command/nslookup?domain=localhost"; p
  get "/api/vuln/xss?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"; p
  get "/api/vuln/ssrf?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"; p
  get "/api/vuln/ssrf?url=http%3A%2F%2F127.0.0.1%3A3000%2Fhealth"; p

  # --- Path / documents / arbitrary read ---
  get "/api/vuln/path?name=package.json"; p
  get "/api/vuln/path?name=..%2F..%2F..%2Fetc%2Fpasswd"; p
  get "/api/vuln/documents?file=readme.txt"; p
  get "/api/vuln/documents?file=..%2F..%2Fetc%2Fhosts"; p
  post_json "/api/vuln/validate-json" '{"files":["/etc/hosts"],"verbose":true}'; p

  # --- Eval / dynamic code paths ---
  post_json "/api/vuln/eval/calc" '{"expression":"2*3+1"}'; p
  post_json "/api/vuln/eval/transform" '{"code":"return x * 2"}'; p
  get "/api/vuln/eval/greet?name=World"; p
  get "/api/vuln/eval/schedule?code=console.log%28%27tick%27%29&delay=100"; p
  get "/api/vuln/eval/require?module=path"; p
  post_json "/api/vuln/eval/compile" '{"source":"return 41"}'; p

  # --- Outbound HTTP / ReDoS / JWT / misconfig / crypto ---
  get "/api/vuln/http-legacy"; p
  get "/api/vuln/http-user-url?url=http%3A%2F%2F127.0.0.1%3A3000%2Fhealth"; p
  get "/api/vuln/regexp/filter?pattern=(a%2B)%2Bb&text=aaaaaaaaaaaaac"; p
  get "/api/vuln/glob?pattern=*.js&value=index.js"; p
  get "/api/vuln/jwt/sign?sub=traffic-demo"; p
  get "/api/vuln/misconfig"; p
  get "/api/vuln/crypto/md5?data=workshop"; p
  get "/api/vuln/crypto/hmac-inline?msg=payload"; p

  # --- Parse / buffer / file write ---
  post_json "/api/vuln/parse/raw-json" '{"raw":"{\"k\":1}"}'; p
  post_json "/api/vuln/buffer/from-user" '{"hex":"41424344"}'; p
  post_json "/api/vuln/files/write-note" '{"name":"_traffic-demo-note.txt","content":"appsec-traffic"}'; p

  get "/health"; p
  get "/api/vuln/"; p
  log "=== Full sweep complete ==="
}

echo "Waiting ${STARTUP_DELAY}s for workshop-app to accept traffic..."
sleep "${STARTUP_DELAY}"

if [ "$LOOP" = 1 ]; then
  log "LOOP=1: continuous traffic (pause ${INTERVAL}s after each full sweep). Set LOOP=0 for a single sweep."
  while true; do
    burst_full
    log "Pausing ${INTERVAL}s before next sweep..."
    sleep "${INTERVAL}"
  done
else
  burst_full
fi
