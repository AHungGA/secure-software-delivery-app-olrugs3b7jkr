/**
 * Express application (workshop). Demo routes live under /api/vuln and /api/pr-gate-demo.
 * Hardened handlers: npm run workshop:apply-secure (see workshop/secure-app).
 */
const express = require('express');
const cookieParser = require('cookie-parser');

const healthRoutes = require('./routes/health');
const vulnRoutes = require('./routes/vuln');
const prGateDemoSink = require('./pr-gate-demo-sink');

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.use('/health', healthRoutes);
app.use('/api/vuln', vulnRoutes);
app.use('/api/pr-gate-demo', prGateDemoSink);

module.exports = app;
