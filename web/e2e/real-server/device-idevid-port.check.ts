/**
 * Unit check of the Device IDevID real-server port, without a browser or a
 * server:
 *
 *   node web/e2e/real-server/device-idevid-port.check.ts
 *
 * (Node strips the types.) device-idevid-port.spec.ts must run against the
 * real-server harness (no route mocks, no mock fixtures, no skips) and must
 * port, or list as a gap or as covered, every case of the mocked Device
 * IDevID describe of web/e2e/devices.spec.ts. Exits non-zero on the first
 * failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const port = fs.readFileSync(path.join(import.meta.dirname, 'device-idevid-port.spec.ts'), 'utf8');

assert.ok(port.includes("from './fixtures'"), "device-idevid-port.spec.ts imports the harness from './fixtures'");

const FORBIDDEN = [
  'page.route(',
  'context.route(',
  'route.fulfill(',
  'api-mock',
  'dashboard-api-mocks',
  'device-api-mock',
  'auth-setup',
  'test.skip(',
];
for (const f of FORBIDDEN) {
  assert.ok(!port.includes(f), `device-idevid-port.spec.ts does not use ${f}`);
}

// Every test title of the mocked `Device IDevID` describe
// (web/e2e/devices.spec.ts), once each.
const MOCKED: string[] = [
  // IDevID Certificate List
  'should display IDevID page with table structure',
  'should show empty state when no certificates',
  'should display Issue IDevID button',
  'should display filter controls',
  // IDevID Filtering UI
  'should allow typing in search field',
  'should open status filter dropdown',
  'should open expiration filter dropdown',
  'should show clear filters button when filter is applied',
  // Issue IDevID Certificate
  'should open issue IDevID dialog',
  'should display issue form with all fields',
  'should validate device selection is required',
  'should validate subject is required',
  'should show RSA key algorithm as default',
  'should switch to ECC algorithm and show curve options',
  'should close dialog on escape key',
  'should issue certificate successfully',
  // IDevID Certificate Actions
  'should open actions menu',
  'should navigate to certificate details',
  'should download certificate',
  'should renew certificate',
  'should revoke certificate with confirmation',
  'should cancel revoke when dialog is dismissed',
  'should not show renew/revoke for non-active certificates',
  // IDevID Error States
  'should show empty state when no certificates exist',
  'should handle revoke certificate error',
  'should handle download certificate error',
  // IDevID Access Control
  'should allow tenant members to view IDevID page',
  'should redirect unauthenticated users to login',
  // IDevID Table Display
  'should display certificate subject',
  'should display serial number in monospace font',
  'should display formatted dates',
  'should display multiple certificates',
];
assert.equal(MOCKED.length, 32, 'MOCKED holds the 32 mocked Device IDevID titles');
for (const t of MOCKED) {
  assert.ok(port.includes(t), `device-idevid-port.spec.ts ports or lists: ${t}`);
}

console.log('device-idevid-port.check: ok');
