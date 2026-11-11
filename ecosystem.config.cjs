/**
 * PM2 config for the workshop app (SSI - Agent injects tracer).
 * Run from repo root: pm2 start ecosystem.config.cjs
 * Ensure .env exists (copy from .env.example) for DD_SERVICE, DD_ENV, DD_VERSION.
 */
const path = require('path');
const dotenvPreload = path.join(__dirname, 'dotenv-load.js');

module.exports = {
  apps: [
    {
      name: 'dash2026-workshop',
      script: path.join(__dirname, 'src/index.js'),
      cwd: __dirname,
      interpreter: 'node',
      node_args: `-r ${dotenvPreload}`,
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      env: {
        NODE_ENV: 'production',
        PORT: '3000',
      },
    },
  ],
};
