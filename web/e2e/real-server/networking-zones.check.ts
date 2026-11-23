/**
 * Unit check of the Network Zones real-server spec, without a browser or a
 * server:
 *
 *   node web/e2e/real-server/networking-zones.check.ts
 *
 * (Node strips the types.) The spec must read back the effect of the update
 * and the delete: after Save Changes it reads the zone through
 * listNetworkZones() and compares its isolate value, and after Delete it
 * proves the zone is absent from the list and the refreshed page.
 * Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const specPath = path.join(import.meta.dirname, 'networking-zones.spec.ts');
const spec = fs.readFileSync(specPath, 'utf8');

assert.ok(
  !spec.includes('does not assert that a deleted zone leaves the list'),
  'networking-zones.spec.ts still says it does not assert that a deleted zone leaves the list',
);

assert.match(
  spec,
  /mutation\(adminPage, 'PUT', zonePath\)[\s\S]*listNetworkZones\(\)[\s\S]*isolate/,
  'after the PUT the spec must read the zone through listNetworkZones() and compare isolate',
);

assert.match(
  spec,
  /mutation\(adminPage, 'DELETE', zonePath\)[\s\S]*listNetworkZones\(\)[\s\S]*not\.toContain\(name\)/,
  'after the DELETE the spec must read listNetworkZones() and assert the name is absent',
);

const afterDelete = spec.slice(spec.indexOf("mutation(adminPage, 'DELETE', zonePath)"));
assert.match(
  afterDelete,
  /toBeHidden\(\)/,
  'after the DELETE the spec must assert the zone row is hidden on the refreshed page',
);

console.log('networking-zones.check: ok');
