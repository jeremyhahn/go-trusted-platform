/**
 * Unit check of the platform real-server spec, without a browser or a server:
 *
 *   node web/e2e/real-server/platform-daemon.check.ts
 *
 * (Node strips the types.) platform-daemon.spec.ts must drive /platform/health
 * and /platform/services against the real daemon (nothing mocked), compare the
 * page with every platform op the slice covers, and never confirm a shutdown,
 * stop or restart: the daemon is shared by every real-server spec.
 * Exits non-zero on the first failure. Refs #2047.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const specPath = path.join(import.meta.dirname, 'platform-daemon.spec.ts');
assert.ok(fs.existsSync(specPath), 'platform-daemon.spec.ts exists next to this check');
const spec = fs.readFileSync(specPath, 'utf8');

// The real-server fixtures, never the mocked ones.
const imports = [...spec.matchAll(/\bfrom\s+'([^']+)'/g)].map((m) => m[1]);
assert.ok(
  [...spec.matchAll(/import\s*\{([^}]*)\}\s*from\s+'\.\/fixtures'/g)].some(
    (m) => /\btest\b/.test(m[1]) && /\bexpect\b/.test(m[1]),
  ),
  "platform-daemon.spec.ts imports test and expect from './fixtures'",
);
for (const from of imports) {
  assert.ok(!from.includes('api-mock'), `platform-daemon.spec.ts imports nothing from api-mock: ${from}`);
  assert.ok(!from.startsWith('../fixtures'), `platform-daemon.spec.ts imports nothing from ../fixtures: ${from}`);
}

// Nothing mocked.
assert.ok(!spec.includes('page.route('), 'platform-daemon.spec.ts has no page.route(');
assert.ok(!spec.includes('.route('), 'platform-daemon.spec.ts has no .route(');

// Both pages.
for (const route of ['/platform/health', '/platform/services']) {
  assert.ok(spec.includes(`goto('${route}')`), `platform-daemon.spec.ts navigates with goto('${route}')`);
}

// Every op the slice compares the page or its capabilities with.
const ops = [
  'GET /api/v1/platform/status',
  '/api/v1/platform/liveness',
  '/api/v1/platform/readiness',
  '/api/v1/platform/version',
  '/api/v1/platform/entity-types',
  '/api/v1/platform/services',
  'POST /api/v1/platform/shutdown',
  'POST /api/v1/platform/services/{service}/start',
  'POST /api/v1/platform/services/{service}/stop',
  'POST /api/v1/platform/services/{service}/restart',
];
for (const op of ops) {
  assert.ok(spec.includes(op), `platform-daemon.spec.ts names ${op}`);
}

// Never confirm an action on the shared daemon.
const confirms = [
  "'Shut down the daemon'",
  'Shut down the daemon',
  "name: 'Stop'",
  "name: 'Restart'",
  'name: /^stop$/i',
  'name: /^restart$/i',
];
for (const confirm of confirms) {
  assert.ok(!spec.includes(confirm), `platform-daemon.spec.ts never clicks the confirm ${confirm}`);
}

console.log('platform-daemon.check: ok');
