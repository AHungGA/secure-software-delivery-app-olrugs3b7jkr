/**
 * Workshop Node app. Routes under /api/vuln (run npm run workshop:apply-secure for hardened handlers).
 * Uses SSI (Agent-injected tracer). For DD_* from .env, use npm start (see dotenv-load.js).
 */
const app = require('./app');
const config = require('./config');

app.listen(config.port, () => {
  console.log(`Workshop app listening on http://localhost:${config.port}`);
  console.log(`API index: http://localhost:${config.port}/api/vuln`);
  console.log(`PR Gate demo (Lab 02): http://localhost:${config.port}/api/pr-gate-demo`);
});
