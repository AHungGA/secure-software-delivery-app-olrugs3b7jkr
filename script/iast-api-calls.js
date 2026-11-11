#!/usr/bin/env node
/**
 * API calls to exercise vulnerable endpoints for IAST (Interactive Application Security Testing).
 * Run the app first (npm start), then run this script so the instrumented app can detect issues.
 *
 * Usage: node script/iast-api-calls.js [baseUrl]
 * Example: node script/iast-api-calls.js http://localhost:3000
 */

const BASE_URL = process.argv[2] || 'http://localhost:3000';

async function request(method, path, options = {}) {
  const url = new URL(path, BASE_URL);
  const init = {
    method,
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  };
  if (options.body && typeof options.body === 'object' && !(options.body instanceof String))
    init.body = JSON.stringify(options.body);
  const res = await fetch(url.toString(), init);
  const text = await res.text();
  return { status: res.status, body: text };
}

async function run() {
  console.log(`IAST API calls → ${BASE_URL}\n`);

  const tests = [
    {
      name: '1. Command injection (/api/vuln/command/ping)',
      run: () => request('GET', `/api/vuln/command/ping?host=127.0.0.1`),
    },
    {
      name: '2. SQL injection (/api/vuln/sql)',
      run: () => request('GET', `/api/vuln/sql?id=1`),
    },
    {
      name: '3. SQL injection POST (/api/vuln/sql)',
      run: () => request('POST', `/api/vuln/sql`, { body: { username: 'alice' } }),
    },
    {
      name: '4. Reflected XSS (/api/vuln/xss)',
      run: () => request('GET', `/api/vuln/xss?q=test%3Cscript%3Ealert(1)%3C%2Fscript%3E`),
    },
    {
      name: '5. Path traversal (/api/vuln/path)',
      run: () => request('GET', `/api/vuln/path?name=package.json`),
    },
    {
      name: '6. SSRF (/api/vuln/ssrf)',
      run: () => request('GET', `/api/vuln/ssrf?url=http%3A%2F%2F127.0.0.1%3A3000%2Fhealth`),
    },
    {
      name: '7. Safe calc (/api/vuln/eval/calc)',
      run: () => request('POST', '/api/vuln/eval/calc', { body: { a: 1, b: 1, op: '+' } }),
    },
    {
      name: '8. Lodash template (/api/vuln/eval/greet)',
      run: () => request('GET', `/api/vuln/eval/greet?name=World`),
    },
    {
      name: '9. Safe transform (/api/vuln/eval/transform)',
      run: () => request('POST', '/api/vuln/eval/transform', { body: { x: 21, op: 'double' } }),
    },
    {
      name: '10. Misconfig exposure (/api/vuln/misconfig)',
      run: () => request('GET', '/api/vuln/misconfig'),
    },
    {
      name: '11. Health check (/health)',
      run: () => request('GET', '/health'),
    },
  ];

  for (const t of tests) {
    try {
      const result = await t.run();
      console.log(`${t.name} → ${result.status}`);
    } catch (err) {
      console.log(`${t.name} → ERROR: ${err.message}`);
    }
  }

  console.log('\nDone. Check your IAST dashboard for findings.');
}

run();
