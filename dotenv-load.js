/**
 * Preload with: node -r ./dotenv-load.js src/index.js
 * For SSI, DD_* must also be in the real OS env *before* node starts — use
 * script/start-workshop-app.sh (sources .env then execs node with this -r).
 */
'use strict';

const fs = require('fs');
const path = require('path');

const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  require('dotenv').config({ path: envPath });
}
