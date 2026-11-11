const express = require('express');
const { getDummyVersion } = require('../dummy');
const pkg = require('../../package.json');

const router = express.Router();

router.get('/', (req, res) => {
  res.json({
    status: 'ok',
    dummy: getDummyVersion(),
    service: process.env.DD_SERVICE || 'dash2026-workshop-app',
    env: process.env.DD_ENV || process.env.NODE_ENV || 'development',
    version: process.env.DD_VERSION || pkg.version,
  });
});

module.exports = router;
