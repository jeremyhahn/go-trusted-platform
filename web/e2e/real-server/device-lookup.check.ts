/**
 * Unit check of the device lookup port, without a browser or a server:
 *
 *   node web/e2e/real-server/device-lookup.check.ts
 *
 * (Node strips the types.) The device lookup page runs on the real server
 * only (#2036): the mocked spec is gone, and every operation the page drives
 * has a real-server test named after it. Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

assert.ok(
  !fs.existsSync(path.join(import.meta.dirname, '..', 'device-lookup.spec.ts')),
  'web/e2e/device-lookup.spec.ts (the mocked device lookup spec) does not exist',
);

const specPath = path.join(import.meta.dirname, 'device-lookup.spec.ts');
assert.ok(fs.existsSync(specPath), 'real-server/device-lookup.spec.ts exists');
const spec = fs.readFileSync(specPath, 'utf8');
assert.ok(spec.includes("from './fixtures'"), "device-lookup.spec.ts imports from './fixtures'");
assert.ok(spec.includes("goto('/devices/lookup/')"), 'device-lookup.spec.ts visits /devices/lookup/');
for (const banned of ['api-mock', 'auth-setup', 'page.route(', 'test.skip(', 'test.fixme(']) {
  assert.ok(!spec.includes(banned), `device-lookup.spec.ts does not use ${banned}`);
}

const operations = [
  'CountDevices',
  'CountProfiles',
  'FindDeviceBySerial',
  'UpdateDevice',
  'AttestDevice',
  'ActivateDevice',
  'GetProfile',
  'FindProfileByMACAddress',
  'FindProfileBySerial',
  'FindMatchingProfile',
  'UpdateProfile',
];
for (const name of operations) {
  const title = new RegExp(`test\\(\\s*['\`"][^'\`"]*${name}`);
  assert.match(spec, title, `device-lookup.spec.ts has a test titled with ${name}`);
}

console.log('device-lookup.check: ok');
