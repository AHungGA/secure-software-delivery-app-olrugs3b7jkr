/**
 * Non-secret app configuration. Workshop only; not for production.
 */
const path = require('path');

module.exports = {
  port: Number(process.env.PORT, 10) || 3000,
  documentsDir: path.join(__dirname, '..', 'documents'),
  /** Insecure demo JWT signing key — not a real credential; use env to override locally. */
  workshopJwtSecret: process.env.WORKSHOP_JWT_SECRET || 'workshop-insecure-jwt-signing-key',
};
