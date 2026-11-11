#!/usr/bin/env bash
#
# Benign patterns aligned with common Datadog Workload Protection — process execution rules
# (see Security → Detection Rules → Workload Protection). Workshop / lab only.
#
# Touches themes such as:
#   - Executable bit added to newly created file
#   - Interactive shell spawned in container (pseudo-TTY via script(1))
#   - DNS lookup for IP lookup / paste-style hostnames
#   - Database-like process spawning a shell (sqlite3 .shell)
#   - Network utility invoking a shell (curl | sh pattern — benign payload only)
#
set -euo pipefail

log() { echo ""; echo "=== $* ==="; }

log "Workshop CWS process-execution demo (standalone container)"
echo "Compose file: docker-compose.cws-proc-demo.yml (not the workshop-app stack)."
echo "Rules catalog: https://docs.datadoghq.com/security/default_rules/?category=cat-workload-protection#all"

# --- Executable bit added to newly created file ---
log "Executable bit added to newly created file"
f="/tmp/dd-new-exec-$$"
umask 022
: >"$f"
chmod a+x "$f"
rm -f "$f"
echo "chmod +x on new file under /tmp, then removed."

# --- Interactive shell spawned in container ---
log "Interactive shell spawned in container (script + bash -i)"
# Feed a single command so bash -i exits without hanging.
printf 'exit 0\n' | script -q -e -c "/bin/bash --norc -i" /dev/null 2>/dev/null || \
  printf 'exit 0\n' | script -q -c "/bin/bash --norc -i" /dev/null 2>/dev/null || true
echo "script(1) session ended."

# --- DNS: IP lookup / geolocation style hostnames ---
log "DNS lookup for IP lookup service style hostnames"
getent ahosts api.ipify.org 2>/dev/null || dig +short A api.ipify.org @8.8.8.8 2>/dev/null || true
getent ahosts ifconfig.me 2>/dev/null || dig +short A ifconfig.me @8.8.8.8 2>/dev/null || true

# --- DNS: paste / sharing style hostnames ---
log "DNS lookup for paste service style hostnames"
getent ahosts pastebin.com 2>/dev/null || dig +short A pastebin.com @8.8.8.8 2>/dev/null || true
getent ahosts paste.ee 2>/dev/null || dig +short A paste.ee @8.8.8.8 2>/dev/null || true

# --- Database process spawned shell ---
log "Database process spawned shell (sqlite3 .shell)"
sqlite3 :memory: ".shell id" 2>/dev/null || echo "sqlite3 .shell not available (unexpected)."
echo "sqlite3 parent with shell child completed."

# --- Network utility + shell (curl | sh — local file URL only, no remote code) ---
log "curl output piped to shell (benign local file:// script)"
printf '%s\n' '#!/bin/sh' 'echo workshop-curl-file-pipe' > /tmp/cws-curl-pipe.sh
chmod +x /tmp/cws-curl-pipe.sh
curl -fsS "file:///tmp/cws-curl-pipe.sh" 2>/dev/null | /bin/sh || true
rm -f /tmp/cws-curl-pipe.sh

echo ""
echo "=== Demo finished. In Datadog: Security → Signals / Cloud Workload Security (process execution) ==="
