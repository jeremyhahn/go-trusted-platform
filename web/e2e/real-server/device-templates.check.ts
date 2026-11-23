/**
 * Unit check of the device templates port, without a browser or a server:
 *
 *   node web/e2e/real-server/device-templates.check.ts
 *
 * (Node strips the types.) The mocked web/e2e/device-templates.spec.ts is
 * gone, and its real-server port drives /devices/templates through the
 * harness fixtures with one test per device template operation (#2036).
 * Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const mocked = path.join(import.meta.dirname, '..', 'device-templates.spec.ts');
assert.ok(!fs.existsSync(mocked), 'the mocked web/e2e/device-templates.spec.ts is deleted');

const ported = path.join(import.meta.dirname, 'device-templates.spec.ts');
assert.ok(fs.existsSync(ported), 'web/e2e/real-server/device-templates.spec.ts exists');

const spec = fs.readFileSync(ported, 'utf8');
for (const want of ["from './fixtures'", "goto('/devices/templates')"]) {
  assert.ok(spec.includes(want), `device-templates.spec.ts includes ${want}`);
}
for (const banned of ['api-mock', 'auth-setup', 'page.route(', 'test.skip(', 'test.fixme(']) {
  assert.ok(!spec.includes(banned), `device-templates.spec.ts does not include ${banned}`);
}

const operations = [
  'CreateTemplate',
  'GetTemplate',
  'UpdateTemplate',
  'DeleteTemplate',
  'CreateProfileFromTemplate',
  'FindConfigForDevice',
  'AssignProfileToDevice',
  'UnassignProfileFromDevice',
];
for (const name of operations) {
  const title = new RegExp(`test\\(\\s*['\`"][^'\`"]*${name}`);
  assert.ok(title.test(spec), `a test title names ${name}`);
}

console.log('device-templates.check: ok');
