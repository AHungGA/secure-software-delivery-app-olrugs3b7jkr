#!/usr/bin/env bash
#
# Cloud Workload Security (CWS / Workload Protection) — generate runtime activity that
# often appears in Datadog default detection rules for workload protection.
#
# Rules catalog (filter "Workload Protection"):
#   https://docs.datadoghq.com/security/default_rules/?category=cat-workload-protection#all
#
# Examples of patterns this lab is designed to surface (exact rule titles vary by release):
#   - Shell or interpreter-spawned subprocesses (e.g. "Shell process created by Java application"
#     — same class of detection for Node when the app uses child_process / sh -c)
#   - Suspicious shell command lines (ping, nslookup, bash -c, chmod on temp files)
#   - Sensitive file reads (e.g. /etc/passwd) from a container context
#   - File Integrity Monitoring (FIM): cron drop-in under /etc/cron.d/ (e.g. "Cron job modified"),
#     chmod on an essential binary in /bin (e.g. "Verify Essential Linux Binary Modified in Container")
#     — see https://docs.datadoghq.com/security/default_rules/a78-b2n-xmd/ and def-000-mpk
#
# Modes (env CWS_DEMO_MODE):
#   http              — default. HTTP only: disposable curl container hits the workshop app
#                       so the Node process spawns shells (Option A + explicit bash-spawn route).
#   http-and-container — HTTP plus, if Docker is available, docker exec into workshop-app
#                       for extra process/exec events and FIM-oriented file/chmod activity.
#
# Usage (from app dir, e.g. /root/lab):
#   npm run lab:trigger-cws-app
#   CWS_DEMO_MODE=http-and-container npm run lab:trigger-cws-app
#   BASE_URL=http://127.0.0.1:3000 npm run lab:trigger-cws-app
#
# FIM-only extras on the running app container (without re-running HTTP):
#   CWS_DEMO_MODE=fim-container npm run lab:trigger-cws-app
#
# Set CWS_TRIGGER_FIM=0 with http-and-container to skip FIM phase (process demo only).
#
# Requires: Docker, curlimages/curl (pulled on first HTTP phase).
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:80}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.5.0}"
CWS_DEMO_MODE="${CWS_DEMO_MODE:-http}"
CWS_TRIGGER_FIM="${CWS_TRIGGER_FIM:-1}"
WORKSHOP_CONTAINER="${WORKSHOP_CONTAINER:-workshop-app}"

echo "CWS demo: BASE_URL=${BASE_URL}  CWS_DEMO_MODE=${CWS_DEMO_MODE}  CWS_TRIGGER_FIM=${CWS_TRIGGER_FIM}"
echo "Reference: https://docs.datadoghq.com/security/default_rules/?category=cat-workload-protection#all"
echo ""

docker_pull_curl() {
  echo "Pulling ${CURL_IMAGE} (if not cached)..."
  docker pull "${CURL_IMAGE}" >/dev/null
}

run_curl() {
  local url=$1
  local label=$2
  echo ""
  echo "=== ${label} ==="
  docker run --rm --network host "${CURL_IMAGE}" -sS -m 25 "${url}" | head -c 500 || true
  echo ""
}

phase_http_node_spawns_shell() {
  echo "Phase 1 — HTTP: Node (workshop-app) handles requests and spawns shell children (CWS-relevant)."
  docker_pull_curl

  run_curl "${BASE_URL}/api/vuln/command/ping?host=127.0.0.1" \
    "GET /api/vuln/command/ping (execSync → sh -c ping)"

  run_curl "${BASE_URL}/api/vuln/command/nslookup?domain=localhost" \
    "GET /api/vuln/command/nslookup (execSync → sh -c nslookup)"

  run_curl "${BASE_URL}/api/vuln/command/exec?cmd=id" \
    "GET /api/vuln/command/exec (exec → shell, cmd=id)"

  run_curl "${BASE_URL}/api/vuln/command/exec?cmd=%2Fbin%2Fbash%20-c%20id" \
    "GET /api/vuln/command/exec (bash -c id)"

  run_curl "${BASE_URL}/api/vuln/workload/bash-spawn?confirm=1" \
    "GET /api/vuln/workload/bash-spawn?confirm=1 (Node → /bin/bash -lc, CWS lab route)"
}

workshop_container_running() {
  command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "${WORKSHOP_CONTAINER}"
}

phase_docker_exec_container() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "Phase 2 — skipped (docker not found)."
    return 0
  fi
  if ! workshop_container_running; then
    echo "Phase 2 — skipped (container '${WORKSHOP_CONTAINER}' not running). Start stack: npm run docker:up"
    return 0
  fi

  echo ""
  echo "Phase 2 — docker exec into ${WORKSHOP_CONTAINER}: extra shell / file / chmod activity (workshop only)."
  set +e

  docker exec "${WORKSHOP_CONTAINER}" /bin/sh -c 'echo cws-docker-exec-sh' || true
  docker exec "${WORKSHOP_CONTAINER}" /bin/bash -lc 'id' || true
  docker exec "${WORKSHOP_CONTAINER}" /bin/sh -c 'head -n 3 /etc/passwd' || true
  docker exec "${WORKSHOP_CONTAINER}" /bin/sh -c 'tmp=/tmp/dd-cws-chmod-demo-$$; touch "$tmp" && chmod 777 "$tmp" && rm -f "$tmp"' || true

  set -e
  echo "Phase 2 — done."
}

# FIM-oriented events inside the app container (Workload Protection file integrity signals).
# OOTB examples: "Cron job modified" (cron files), binary permission changes under /bin.
phase_fim_container() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "Phase 3 (FIM) — skipped (docker not found)."
    return 0
  fi
  if ! workshop_container_running; then
    echo "Phase 3 (FIM) — skipped (container '${WORKSHOP_CONTAINER}' not running)."
    return 0
  fi

  echo ""
  echo "Phase 3 (FIM) — file integrity style activity in ${WORKSHOP_CONTAINER} (workshop only; immediately reverted)."
  set +e

  # Cron drop-in create + delete — aligns with default "Cron job modified" style detections.
  docker exec "${WORKSHOP_CONTAINER}" /bin/sh -c \
    'printf "%s\n" "@reboot root /bin/true" > /etc/cron.d/workshop-fim-demo && rm -f /etc/cron.d/workshop-fim-demo' || true

  # chmod on an essential binary then restore 755 — aligns with "Verify Essential Linux Binary Modified in Container".
  docker exec "${WORKSHOP_CONTAINER}" /bin/sh -c 'chmod 744 /bin/cat && chmod 755 /bin/cat' || true

  set -e
  echo "Phase 3 (FIM) — done. Datadog: Security → Signals (FIM / file integrity / cron / container drift)."
}

phase_http_node_spawns_shell

case "${CWS_DEMO_MODE}" in
  http)
    if [[ "${CWS_TRIGGER_FIM}" != "1" ]]; then
      echo "Phase 3 (FIM) — skipped (CWS_TRIGGER_FIM=${CWS_TRIGGER_FIM})."
    elif ! workshop_container_running; then
      echo "Phase 3 (FIM) — skipped (Docker container '${WORKSHOP_CONTAINER}' not found; FIM needs the Compose app running)."
    else
      phase_fim_container
    fi
    ;;
  http-and-container)
    phase_docker_exec_container
    if [[ "${CWS_TRIGGER_FIM}" == "1" ]]; then
      phase_fim_container
    fi
    ;;
  fim-container)
    phase_fim_container
    ;;
  *)
    echo "Unknown CWS_DEMO_MODE='${CWS_DEMO_MODE}'. Use: http | http-and-container | fim-container" >&2
    exit 1
    ;;
esac

echo ""
echo "Done. In Datadog: Security → Signals / Cloud Workload Security — look for process activity"
echo "from ${WORKSHOP_CONTAINER} or your Node service (shell children, suspicious args)."
