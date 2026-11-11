/**
 * Same route layout as the workshop “vuln” API, implemented with safe patterns.
 * Replace vulnerable src files via: npm run workshop:apply-secure
 */
const path = require('path');
const fs = require('fs');
const { readFile } = require('fs').promises;
const express = require('express');
const { execFileSync } = require('child_process');
const _ = require('lodash');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const micromatch = require('micromatch');

const config = require('../config');
const mockDb = require('../lib/mockDb');

const router = express.Router();

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function resolveUnderRoot(rootDir, userSegment) {
  const raw = String(userSegment || '');
  if (raw.includes('..') || path.isAbsolute(raw)) return null;
  const safeName = path.basename(raw);
  if (!safeName) return null;
  const resolved = path.resolve(path.join(rootDir, safeName));
  const root = path.resolve(rootDir);
  if (!resolved.startsWith(root + path.sep) && resolved !== root) return null;
  return resolved;
}

// --- SQL-shaped routes: structured lookups only ---

router.get('/sql', (req, res) => {
  const id = req.query.id ?? '1';
  const row = mockDb.findUserById(id);
  if (!row) {
    return res.status(400).json({ error: 'Invalid or unknown id', query: mockDb.describeQuery('byId', { id }) });
  }
  res.json({ rows: [row], note: 'secure: no concatenated SQL' });
});

router.post('/sql', (req, res) => {
  const username = req.body.username ?? req.body.user ?? 'guest';
  const row = mockDb.findUserByUsername(String(username));
  if (!row) {
    return res.status(400).json({ error: 'Invalid username or not found', query: mockDb.describeQuery('byUsername', {}) });
  }
  res.json({ rows: [row], note: 'secure: validated username' });
});

const ALLOWED_SQL_SEARCH = {
  table: ['users'],
  column: ['username', 'id'],
};

router.post('/sql-search', (req, res) => {
  let { table = 'users', column = 'name', value = '' } = req.body;
  table = String(table);
  column = String(column);
  if (!ALLOWED_SQL_SEARCH.table.includes(table) || !ALLOWED_SQL_SEARCH.column.includes(column)) {
    return res.status(400).json({ error: 'table/column not allowed' });
  }
  if (column === 'id') {
    const row = mockDb.findUserById(value);
    return row ? res.json({ rows: [row] }) : res.status(404).json({ rows: [] });
  }
  const row = mockDb.findUserByUsername(value);
  return row ? res.json({ rows: [row] }) : res.status(404).json({ rows: [] });
});

// --- Command-style routes: strict allowlist, execFile (no shell), no user-controlled argv joining ---

router.get('/command/ping', (req, res) => {
  const host = req.query.host || '127.0.0.1';
  if (host !== '127.0.0.1' && host !== '::1') {
    return res.status(400).type('text/plain').send('Only 127.0.0.1 or ::1 allowed');
  }
  try {
    const result = execFileSync('ping', ['-c', '4', host], { encoding: 'utf8' });
    res.type('text/plain').send(result);
  } catch (e) {
    res.status(500).type('text/plain').send(String(e.message));
  }
});

router.get('/command/nslookup', (req, res) => {
  const domain = String(req.query.domain || 'localhost');
  if (!/^[a-zA-Z0-9.-]{1,253}$/.test(domain)) {
    return res.status(400).type('text/plain').send('Invalid domain');
  }
  try {
    const result = execFileSync('nslookup', [domain], { encoding: 'utf8' });
    res.type('text/plain').send(result);
  } catch (e) {
    res.status(500).type('text/plain').send(String(e.message));
  }
});

router.get('/xss', (req, res) => {
  const q = req.query.q || '';
  const safe = escapeHtml(q);
  res.type('html').send(`<!DOCTYPE html>
<html><body>
  <h1>Search results for: ${safe}</h1>
  <p>No results found.</p>
</body></html>`);
});

router.get('/path', (req, res) => {
  const repoRoot = path.join(__dirname, '..', '..');
  const resolved = resolveUnderRoot(repoRoot, req.query.name || 'package.json');
  if (!resolved) {
    return res.status(400).type('text/plain').send('Invalid path');
  }
  try {
    const content = fs.readFileSync(resolved, 'utf8');
    res.type('text/plain').send(content);
  } catch (e) {
    res.status(404).type('text/plain').send('Not found');
  }
});

router.get('/documents', (req, res) => {
  const resolved = resolveUnderRoot(config.documentsDir, req.query.file || 'readme.txt');
  if (!resolved) {
    return res.status(400).type('text/plain').send('Invalid file');
  }
  try {
    const content = fs.readFileSync(resolved, 'utf8');
    res.type('text/plain').send(content);
  } catch (e) {
    res.status(404).type('text/plain').send('Not found');
  }
});

router.post('/validate-json', async (req, res) => {
  const files = Array.isArray(req.body.files) ? req.body.files : [req.body.file].filter(Boolean);
  const verbose = Boolean(req.body.verbose || req.query.verbose);
  if (files.length === 0) {
    return res.status(400).json({ error: 'Provide "files" (array) or "file" in body' });
  }
  const allowedRoot = path.resolve(path.join(__dirname, '..', '..', 'documents'));
  const results = await Promise.all(
    files.map(async (file) => {
      const fp = resolveUnderRoot(allowedRoot, file);
      if (!fp) {
        return { file, valid: false, error: 'Path not allowed' };
      }
      try {
        const data = await readFile(fp, 'utf8');
        JSON.parse(data);
        return { file, valid: true, ...(verbose && { size: data.length }) };
      } catch (err) {
        return { file, valid: false, error: err.message };
      }
    }),
  );
  res.json({ results });
});

router.post('/eval/calc', (req, res) => {
  const a = Number(req.body.a);
  const b = Number(req.body.b);
  const op = String(req.body.op || '+');
  if (!Number.isFinite(a) || !Number.isFinite(b) || !['+', '-', '*', '/'].includes(op)) {
    return res.status(400).json({ error: 'Send numeric a, b and op in + - * /' });
  }
  let result;
  switch (op) {
    case '+':
      result = a + b;
      break;
    case '-':
      result = a - b;
      break;
    case '*':
      result = a * b;
      break;
    default:
      result = b === 0 ? null : a / b;
  }
  if (result === null) return res.status(400).json({ error: 'Division by zero' });
  res.json({ result });
});

router.post('/eval/transform', (req, res) => {
  const x = Number(req.body.x ?? 42);
  const op = String(req.body.op || 'double');
  if (!Number.isFinite(x)) return res.status(400).json({ error: 'Invalid x' });
  const allowed = { double: (n) => n * 2, neg: (n) => -n, abs: (n) => Math.abs(n) };
  if (!allowed[op]) return res.status(400).json({ error: 'op must be double|neg|abs' });
  res.json({ output: allowed[op](x) });
});

router.get('/eval/greet', (req, res) => {
  const name = req.query.name || 'Guest';
  const escaped = _.escape(String(name).slice(0, 200));
  res.type('html').send(`Hello, ${escaped}!`);
});

router.get('/eval/schedule', (req, res) => {
  const delay = parseInt(req.query.delay, 10) || 1000;
  if (delay < 0 || delay > 60_000) return res.status(400).json({ error: 'delay 0..60000' });
  setTimeout(() => {}, delay);
  res.json({ scheduled: true });
});

const ALLOWED_BUILTIN_MODULES = new Set(['path', 'fs', 'crypto', 'util']);

router.get('/eval/require', (req, res) => {
  const moduleName = String(req.query.module || 'path');
  if (!ALLOWED_BUILTIN_MODULES.has(moduleName)) {
    return res.status(400).json({ error: 'module not in allowlist' });
  }
  const mod = require(moduleName);
  res.json({ module: moduleName, loaded: typeof mod });
});

const ALLOWED_SSRF_URL = 'http://127.0.0.1:3000/health';

router.get('/ssrf', async (req, res) => {
  const target = req.query.url || ALLOWED_SSRF_URL;
  if (target !== ALLOWED_SSRF_URL) {
    return res.status(400).json({ error: 'url not allowed' });
  }
  try {
    const { data, status } = await axios.get(target, { timeout: 5000, validateStatus: () => true });
    res.json({ url: target, status, data });
  } catch (err) {
    res.status(502).json({ url: target, error: err.message });
  }
});

router.get('/http-legacy', async (req, res) => {
  try {
    const { data } = await axios.get('https://example.com', { timeout: 5000, maxRedirects: 3 });
    res.json({ via: 'https', bytes: typeof data === 'string' ? data.length : 0 });
  } catch (err) {
    res.status(502).json({ error: err.message || 'Request failed' });
  }
});

router.get('/misconfig', (req, res) => {
  res.json({
    nodeEnv: process.env.NODE_ENV,
    secureWorkshopMode: true,
  });
});

router.get('/glob', (req, res) => {
  const pattern = String(req.query.pattern || '*.js').slice(0, 80);
  const value = String(req.query.value || 'index.js').slice(0, 200);
  try {
    const matched = micromatch.contains(value, pattern);
    res.json({ pattern, value, matched });
  } catch {
    res.status(400).json({ error: 'Invalid pattern' });
  }
});

router.get('/jwt/sign', (req, res) => {
  const payload = { sub: String(req.query.sub || 'user').slice(0, 128), iat: Math.floor(Date.now() / 1000) };
  const token = jwt.sign(payload, config.workshopJwtSecret, { expiresIn: '1h' });
  res.json({ token });
});

router.get('/', (req, res) => {
  res.json({
    message: 'Workshop API routes (secure build — no intentional exploit patterns)',
    applyScript: 'npm run workshop:apply-secure',
    endpoints: [
      { method: 'GET', path: '/sql', note: '?id= numeric user lookup' },
      { method: 'POST', path: '/sql', note: 'body.username (alphanumeric)' },
      { method: 'POST', path: '/sql-search', note: 'allowlisted table/column' },
      { method: 'GET', path: '/command/ping', note: 'localhost only' },
      { method: 'GET', path: '/command/nslookup', note: 'restricted domain chars' },
      { method: 'GET', path: '/xss', note: 'HTML escaped' },
      { method: 'GET', path: '/path', note: 'basename under repo root' },
      { method: 'GET', path: '/documents', note: 'under documents/ only' },
      { method: 'POST', path: '/validate-json', note: 'paths under documents/ only' },
      { method: 'POST', path: '/eval/calc', note: 'a, b, op (no eval)' },
      { method: 'POST', path: '/eval/transform', note: 'fixed ops only' },
      { method: 'GET', path: '/eval/greet', note: 'lodash.escape' },
      { method: 'GET', path: '/eval/schedule', note: 'numeric delay only' },
      { method: 'GET', path: '/eval/require', note: 'builtin allowlist' },
      { method: 'GET', path: '/ssrf', note: 'fixed internal URL only' },
      { method: 'GET', path: '/http-legacy', note: 'HTTPS outbound' },
      { method: 'GET', path: '/misconfig', note: 'minimal' },
      { method: 'GET', path: '/glob', note: 'pattern size cap' },
      { method: 'GET', path: '/jwt/sign', note: 'JWT sign' },
    ],
  });
});

module.exports = router;
