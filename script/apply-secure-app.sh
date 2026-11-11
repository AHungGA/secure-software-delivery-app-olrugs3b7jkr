#!/usr/bin/env bash
# Copy hardened workshop API implementation over src/ (same routes, safe handlers).
#
# Source: workshop/secure-app/
# Targets:  src/routes/vuln.js, src/lib/mockDb.js
#
# Usage (repo root):
#   bash script/apply-secure-app.sh
#   npm run workshop:apply-secure
#
# Reverting to the vulnerable teaching version: use git checkout -- src/routes/vuln.js src/lib/mockDb.js
# (or restore from a branch / commit that still contains the intentional patterns).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT}/workshop/secure-app"
DST_ROUTES="${ROOT}/src/routes/vuln.js"
DST_LIB="${ROOT}/src/lib/mockDb.js"

if [[ ! -f "${SRC}/routes/vuln.js" ]] || [[ ! -f "${SRC}/lib/mockDb.js" ]]; then
  echo "ERROR: Missing ${SRC}/routes/vuln.js or lib/mockDb.js" >&2
  exit 1
fi

cp -f "${SRC}/routes/vuln.js" "${DST_ROUTES}"
cp -f "${SRC}/lib/mockDb.js" "${DST_LIB}"
echo "Installed secure routes → ${DST_ROUTES}"
echo "Installed secure mock DB  → ${DST_LIB}"

if [[ -d "${ROOT}/node_modules/express" ]]; then
  node -e "require('${ROOT}/src/app'); console.log('Smoke check: app loads OK.')"
else
  echo "Skip smoke check (run npm install first)."
fi
