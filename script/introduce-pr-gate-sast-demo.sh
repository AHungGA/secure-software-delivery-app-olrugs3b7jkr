#!/usr/bin/env bash
# Overwrites src/pr-gate-demo-sink.js with the Lab 02 path-traversal demo router (PR Gate / SAST).
# Run from repo root (e.g. cd /root/lab && bash script/introduce-pr-gate-sast-demo.sh)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${ROOT}/src/pr-gate-demo-sink.js"

cat > "${TARGET}" <<'EOF'
/**
 * PR Gate workshop — intentional path-traversal demo (Lab 02). Mounted at `/api/pr-gate-demo`.
 * Not hardened; do not expose to untrusted networks.
 */
const fs = require('fs');
const express = require('express');
const path = require('path');

const router = express.Router();
const BASE_DIR = path.join(__dirname, '..');

router.get('/read', (req, res) => {
  const filename = req.query.file;
  const filepath = BASE_DIR + '/' + filename;
  fs.readFile(filepath, 'utf8', (err, data) => {
    if (err) return res.status(500).send(err.message);
    res.send(data);
  });
});

module.exports = router;
EOF

echo "Wrote ${TARGET}"
echo "Stage and commit on your PR branch to introduce a new SAST finding on the diff."
