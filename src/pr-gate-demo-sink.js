/**
 * PR Gate workshop — new file for diff-aware Static Code Analysis only.
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