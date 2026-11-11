/**
 * PR Gate workshop — placeholder until Lab 02 replaces this module.
 * Mounted at `/api/pr-gate-demo` (see `src/app.js`).
 */
const express = require('express');

const router = express.Router();

router.get('/', (req, res) => {
  res.type('text/plain').send(
    'PR Gate demo: in Lab 02, replace this file with the vulnerable `/read` handler exercise.',
  );
});

module.exports = router;
