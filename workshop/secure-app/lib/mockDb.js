/**
 * In-memory user store with safe lookups (no string-built SQL).
 */
const users = [
  { id: 1, username: 'alice', role: 'user' },
  { id: 2, username: 'bob', role: 'user' },
  { id: 3, username: 'admin', role: 'admin' },
];

const USERNAME_RE = /^[a-zA-Z0-9_-]{1,64}$/;

function findUserById(id) {
  const n = parseInt(String(id), 10);
  if (Number.isNaN(n) || n < 1 || n > 1e9) return null;
  return users.find((u) => u.id === n) || null;
}

function findUserByUsername(username) {
  const u = String(username);
  if (!USERNAME_RE.test(u)) return null;
  return users.find((x) => x.username === u) || null;
}

/** Fixed demo query text for logging only (no user-controlled fragments). */
function describeQuery(kind, meta) {
  return JSON.stringify({ kind, meta });
}

module.exports = {
  users,
  findUserById,
  findUserByUsername,
  describeQuery,
};
