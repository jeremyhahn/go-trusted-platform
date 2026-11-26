/**
 * Unit check of the platform config real-server spec, without a browser or a
 * server:
 *
 *   node web/e2e/real-server/platform-config.check.ts
 *
 * (Node strips the types.) platform-config.spec.ts must drive /platform/config
 * against the real daemon (nothing mocked), compare the page with
 * GET /api/v1/platform/config and the Reload and Apply gates with
 * GET /api/v1/capabilities, and never click a write: the daemon is shared by
 * every real-server spec. Exits non-zero on the first failure. Refs #2047.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const specPath = path.join(import.meta.dirname, 'platform-config.spec.ts');
assert.ok(fs.existsSync(specPath), 'platform-config.spec.ts exists next to this check');
const spec = fs.readFileSync(specPath, 'utf8');

// The real-server fixtures, never the mocked ones.
const imports = [...spec.matchAll(/\bfrom\s+'([^']+)'/g)].map((m) => m[1]);
assert.ok(
  [...spec.matchAll(/import\s*\{([^}]*)\}\s*from\s+'\.\/fixtures'/g)].some(
    (m) => /\btest\b/.test(m[1]) && /\bexpect\b/.test(m[1]),
  ),
  "platform-config.spec.ts imports test and expect from './fixtures'",
);
for (const from of imports) {
  assert.ok(!from.includes('api-mock'), `platform-config.spec.ts imports nothing from api-mock: ${from}`);
  assert.ok(!from.startsWith('../fixtures'), `platform-config.spec.ts imports nothing from ../fixtures: ${from}`);
}

// Nothing mocked.
assert.ok(!spec.includes('page.route('), 'platform-config.spec.ts has no page.route(');
assert.ok(!spec.includes('.route('), 'platform-config.spec.ts has no .route(');

// The page.
assert.ok(spec.includes("goto('/platform/config')"), "platform-config.spec.ts navigates with goto('/platform/config')");

// Every op the slice compares the page or its capabilities with.
const ops = [
  'GET /api/v1/platform/config',
  'POST /api/v1/platform/config/reload',
  'PUT /api/v1/platform/config/sections/{section}',
  'GET /api/v1/capabilities',
];
for (const op of ops) {
  assert.ok(spec.includes(op), `platform-config.spec.ts names ${op}`);
}

// Never click a write on the shared daemon, and never skip.
const forbidden = [
  "name: 'Reload'",
  'name: /reload/i',
  "name: 'Apply'",
  'name: /apply/i',
  "name: 'Snapshot'",
  'name: /snapshot/i',
  'Roll back to this snapshot',
  'Delete snapshot',
  'test.skip',
];
for (const text of forbidden) {
  assert.ok(!spec.includes(text), `platform-config.spec.ts never contains ${text}`);
}
assert.ok(
  !/\b(reload|apply)\w*\.click\(/i.test(spec),
  'platform-config.spec.ts never clicks a reload or apply locator',
);

console.log('platform-config.check: ok');
