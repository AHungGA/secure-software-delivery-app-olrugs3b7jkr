/**
 * Intentionally vulnerable HTTP handlers for SAST and API Protection exercises.
 * Do not deploy to production or expose to the internet without isolation.
 */
const path = require('path');
const fs = require('fs');
const { readFile } = require('fs').promises;
const express = require('express');
const crypto = require('crypto');
const { execSync, exec } = require('child_process');
const _ = require('lodash');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const micromatch = require('micromatch');

const config = require('../config');
const mockDb = require('../lib/mockDb');

const router = express.Router();

/** Workshop-only fake credential — intentional hardcoded-secret / weak-key pattern for SAST demos. */
const WORKSHOP_HARDCODED_HMAC_KEY = 'workshop-hardcoded-hmac-not-for-production';

// --- SQL injection (string concatenation) ---

router.get('/sql', (req, res) => {
  const id = req.query.id ?? '1';
  const sql = mockDb.findUserByIdUnsafe(id);
  const result = mockDb.runRawSql(sql);
  res.json({ sql, ...result });
});

router.post('/sql', (req, res) => {
  const username = req.body.username ?? req.body.user ?? 'guest';
  const sql = mockDb.findByUsernameUnsafe(String(username));
  const result = mockDb.runRawSql(sql);
  res.json({ sql, ...result });
});

router.post('/sql-search', (req, res) => {
  const { table = 'users', column = 'name', value = '' } = req.body;
  // VULNERABLE: multiple parameters concatenated into SQL
  const sql = `SELECT * FROM ${table} WHERE ${column} = '${value}'`;
  const result = mockDb.runRawSql(sql);
  res.json({ sql, ...result });
});

// --- Command injection ---

router.get('/command/ping', (req, res) => {
  const host = req.query.host || '127.0.0.1';
  const result = execSync(`ping -c 4 ${host}`, { encoding: 'utf8' });
  res.type('text/plain').send(result);
});

router.get('/command/nslookup', (req, res) => {
  const domain = req.query.domain || 'localhost';
  const result = execSync(`nslookup ${domain}`, { encoding: 'utf8' });
  res.type('text/plain').send(result);
});

// Uses child_process.exec (shell) — second command-injection sink for rules that match exec() not execSync
router.get('/command/exec', (req, res) => {
  const cmd = req.query.cmd || 'echo workshop-exec';
  exec(cmd, { timeout: 8000, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).type('text/plain').send(stderr || err.message);
    }
    res.type('text/plain').send(stdout || '');
  });
});

// --- Workload Protection (CWS) lab: Node spawns bash ---
// Similar in spirit to "Shell process created by Java application" — parent is node, child is bash.
// Use only in your own lab. Call with ?confirm=1 so traffic is deliberate.
router.get('/workload/bash-spawn', (req, res) => {
  if (String(req.query.confirm) !== '1') {
    return res.status(400).type('text/plain').send(
      'Workload Protection demo: add ?confirm=1 to run a benign `/bin/bash -lc` from this Node process (for CWS / runtime security signals).',
    );
  }
  const out = execSync('/bin/bash -lc "echo cws-workshop-demo"', {
    encoding: 'utf8',
    timeout: 5000,
  });
  res.type('text/plain').send(out.trim());
});

// --- Reflected XSS ---

router.get('/xss', (req, res) => {
  const q = req.query.q || '';
  res.type('html').send(`
    <!DOCTYPE html>
    <html><body>
      <h1>Search results for: ${q}</h1>
      <p>No results found.</p>
    </body></html>
  `);
});

// --- Path traversal (repo-relative) ---

router.get('/path', (req, res) => {
  const filename = req.query.name || 'package.json';
  const filepath = path.join(__dirname, '..', '..', filename);
  const content = fs.readFileSync(filepath, 'utf8');
  res.type('text/plain').send(content);
});

router.get('/documents', (req, res) => {
  const filename = req.query.file || 'readme.txt';
  const filepath = path.join(config.documentsDir, filename);
  const content = fs.readFileSync(filepath, 'utf8');
  res.type('text/plain').send(content);
});

router.post('/validate-json', async (req, res) => {
  const files = Array.isArray(req.body.files) ? req.body.files : [req.body.file].filter(Boolean);
  const verbose = Boolean(req.body.verbose || req.query.verbose);
  if (files.length === 0) {
    return res.status(400).json({ error: 'Provide "files" (array) or "file" in body' });
  }
  const results = await Promise.all(
    files.map(async (file) => {
      try {
        const data = await readFile(file, 'utf8');
        JSON.parse(data);
        return { file, valid: true, ...(verbose && { size: data.length }) };
      } catch (err) {
        return { file, valid: false, error: err.message };
      }
    }),
  );
  res.json({ results });
});

// --- Code execution ---

router.post('/eval/calc', (req, res) => {
  const expr = req.body.expression || '1+1';
  const result = eval(expr);
  res.json({ result });
});

router.post('/eval/transform', (req, res) => {
  const code = req.body.code || 'return x';
  const fn = new Function('x', code);
  res.json({ output: fn(42) });
});

router.get('/eval/greet', (req, res) => {
  const name = req.query.name || 'Guest';
  const compiled = _.template('Hello, <%= name %>!');
  const greeting = compiled({ name });
  res.send(greeting);
});

router.get('/eval/schedule', (req, res) => {
  const code = req.query.code || 'console.log("tick")';
  const delay = parseInt(req.query.delay, 10) || 1000;
  setTimeout(code, delay);
  res.json({ scheduled: true });
});

router.get('/eval/require', (req, res) => {
  const moduleName = req.query.module || 'path';
  const mod = require(moduleName);
  res.json({ module: moduleName, loaded: typeof mod });
});

router.post('/eval/compile', (req, res) => {
  const src = req.body.source || 'return 1';
  res.json({ result: new Function(src)() });
});

// --- SSRF (user-controlled URL) ---

router.get('/ssrf', async (req, res) => {
  const target = req.query.url || 'http://127.0.0.1:3000/health';
  try {
    const { data, status } = await axios.get(target, { timeout: 5000, validateStatus: () => true });
    res.json({ url: target, status, data });
  } catch (err) {
    res.status(502).json({ url: target, error: err.message });
  }
});

// --- Insecure outbound HTTP (no TLS) — SAST: avoid http ---

router.get('/http-legacy', async (req, res) => {
  try {
    const { data } = await axios.get('http://127.0.0.1:3000/health', { timeout: 5000 });
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: err.message || 'Request failed' });
  }
});

router.get('/http-user-url', async (req, res) => {
  const url = req.query.url || 'http://127.0.0.1:3000/health';
  try {
    const { data } = await axios.get(url, { timeout: 5000, validateStatus: () => true });
    res.json({ url, data });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// --- Weak crypto & hardcoded key patterns ---

router.get('/crypto/md5', (req, res) => {
  const data = req.query.data || 'workshop';
  const hash = crypto.createHash('md5').update(String(data)).digest('hex');
  res.json({ algorithm: 'md5', hash });
});

router.get('/crypto/hmac-inline', (req, res) => {
  const msg = req.query.msg || 'payload';
  const sig = crypto.createHmac('sha1', WORKSHOP_HARDCODED_HMAC_KEY).update(String(msg)).digest('hex');
  res.json({ sig });
});

// --- Unsafe parse / RegExp / Buffer ---

router.post('/parse/raw-json', (req, res) => {
  const raw = typeof req.body === 'string' ? req.body : req.body.raw || '{}';
  const obj = JSON.parse(raw);
  res.json({ keys: Object.keys(obj) });
});

router.get('/regexp/filter', (req, res) => {
  const pattern = req.query.pattern || '.*';
  const haystack = req.query.text || 'abc';
  const re = new RegExp(pattern);
  res.json({ matched: re.test(haystack), pattern });
});

router.post('/buffer/from-user', (req, res) => {
  const input = req.body.hex || req.body.data || '414243';
  const buf = Buffer.from(input, 'hex');
  res.json({ length: buf.length });
});

router.post('/files/write-note', (req, res) => {
  const name = req.body.name || 'note.txt';
  const body = String(req.body.content || '');
  const target = path.join(config.documentsDir, name);
  fs.writeFileSync(target, body, 'utf8');
  res.json({ written: target });
});

// --- Information disclosure / misconfig (no real secrets) ---

router.get('/misconfig', (req, res) => {
  res.json({
    nodeEnv: process.env.NODE_ENV,
    stackTracesEnabled: true,
    verboseErrors: true,
    workshopMode: true,
  });
});

// --- Dependency-related patterns (ReDoS / JWT) ---

router.get('/glob', (req, res) => {
  const pattern = req.query.pattern || '*.js';
  const value = req.query.value || 'index.js';
  const matched = micromatch.contains(value, pattern);
  res.json({ pattern, value, matched });
});

router.get('/jwt/sign', (req, res) => {
  const payload = { sub: req.query.sub || 'user', iat: Math.floor(Date.now() / 1000) };
  const token = jwt.sign(payload, config.workshopJwtSecret, { expiresIn: '1h' });
  res.json({ token });
});

// --- Reference list for scanners / humans ---

router.get('/', (req, res) => {
  res.json({
    message: 'Intentionally vulnerable API routes (workshop only)',
    endpoints: [
      { method: 'GET', path: '/sql', note: 'SQLi via ?id=' },
      { method: 'POST', path: '/sql', note: 'SQLi via body username' },
      { method: 'POST', path: '/sql-search', note: 'SQLi via table/column/value' },
      { method: 'GET', path: '/command/ping', note: 'Command injection ?host=' },
      { method: 'GET', path: '/command/nslookup', note: 'Command injection ?domain=' },
      { method: 'GET', path: '/command/exec', note: 'exec() shell ?cmd=' },
      { method: 'GET', path: '/workload/bash-spawn', note: 'CWS demo: node spawns bash ?confirm=1' },
      { method: 'GET', path: '/xss', note: 'Reflected XSS ?q=' },
      { method: 'GET', path: '/path', note: 'Path traversal ?name=' },
      { method: 'GET', path: '/documents', note: 'CWE-22 ?file=' },
      { method: 'POST', path: '/validate-json', note: 'Arbitrary file read via body.files' },
      { method: 'POST', path: '/eval/calc', note: 'eval() body.expression' },
      { method: 'POST', path: '/eval/transform', note: 'Function() body.code' },
      { method: 'GET', path: '/eval/greet', note: 'lodash.template ?name=' },
      { method: 'GET', path: '/eval/schedule', note: 'setTimeout string ?code=' },
      { method: 'GET', path: '/eval/require', note: 'dynamic require ?module=' },
      { method: 'POST', path: '/eval/compile', note: 'new Function(body.source)' },
      { method: 'GET', path: '/ssrf', note: 'SSRF ?url=' },
      { method: 'GET', path: '/http-legacy', note: 'axios to http://' },
      { method: 'GET', path: '/http-user-url', note: 'axios.get(user url)' },
      { method: 'GET', path: '/crypto/md5', note: 'MD5 ?data=' },
      { method: 'GET', path: '/crypto/hmac-inline', note: 'HMAC-SHA1 hardcoded key' },
      { method: 'POST', path: '/parse/raw-json', note: 'JSON.parse(raw user string)' },
      { method: 'GET', path: '/regexp/filter', note: 'RegExp from ?pattern=' },
      { method: 'POST', path: '/buffer/from-user', note: 'Buffer.from(hex)' },
      { method: 'POST', path: '/files/write-note', note: 'writeFile under documents ?name=' },
      { method: 'GET', path: '/misconfig', note: 'verbose settings exposure' },
      { method: 'GET', path: '/glob', note: 'micromatch / ReDoS pattern' },
      { method: 'GET', path: '/jwt/sign', note: 'JWT sign (vulnerable dep version)' },
    ],
  });
});

module.exports = router;
