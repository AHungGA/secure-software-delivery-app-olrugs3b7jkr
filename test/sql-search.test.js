const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { isBuiltin } = require('node:module');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { users } = require('../src/lib/mockDb');

// Load the real route with an Express registration stub, without external dependencies.
const handlers = new Map();
const router = {
  get() {},
  post(route, handler) { handlers.set(route, handler); },
};
const filename = path.join(__dirname, '../src/routes/vuln.js');
vm.runInNewContext(readFileSync(filename, 'utf8'), {
  module: { exports: {} },
  require(name) {
    if (name === 'express') return { Router: () => router };
    if (name === '../lib/mockDb') {
      return {
        users,
        runRawSql() { assert.fail('SQL search must not execute raw SQL'); },
      };
    }
    return isBuiltin(name) ? require(name) : {};
  },
}, { filename });

function search(body) {
  const response = {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(data) { this.body = JSON.parse(JSON.stringify(data)); return this; },
  };
  handlers.get('/sql-search')({ body }, response);
  return response;
}

test('searches supported fields with literal equality', () => {
  for (const [column, value, expected] of [
    ['username', 'alice', [users[0]]],
    ['id', 2, [users[1]]],
    ['id', '2', [users[1]]],
    ['role', 'user', users.slice(0, 2)],
    ['username', 'missing', []],
  ]) {
    const result = search({ table: 'users', column, value });
    assert.equal(result.statusCode, 200);
    assert.deepEqual(result.body, { rows: expected });
  }
});

test('defaults to the users table and username column', () => {
  assert.deepEqual(search({ value: 'alice' }).body, { rows: [users[0]] });
  for (const body of [{}, null, undefined]) {
    assert.deepEqual(search(body).body, { rows: [] });
  }
});

test('rejects injected, unsupported and non-string identifiers', () => {
  for (const table of ["users; DROP TABLE users; --", 'other', '__proto__', {}, [], null]) {
    assert.equal(search({ table, value: 'alice' }).statusCode, 400);
  }
  for (const column of ["username OR 1=1 --", 'constructor', '__proto__', 'toString', {}, [], null]) {
    assert.equal(search({ column, value: 'alice' }).statusCode, 400);
  }
});

test('treats SQL injection values as literal data', () => {
  for (const value of ["' OR '1'='1", "alice'; DROP TABLE users; --", "alice' --", '1 OR 1=1', "O'Reilly", '\\']) {
    for (const column of ['username', 'id', 'role']) {
      const result = search({ column, value });
      assert.equal(result.statusCode, 200);
      assert.deepEqual(result.body, { rows: [] });
    }
  }
});

test('rejects non-scalar values without coercing them', () => {
  for (const value of [null, [], ['alice'], {}, true, NaN, Infinity,
    { toString() { throw new Error('must not coerce objects'); } }]) {
    assert.equal(search({ value }).statusCode, 400);
  }
});
