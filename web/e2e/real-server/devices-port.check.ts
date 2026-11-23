/**
 * Unit check of the Devices Management real-server port, without a browser or a server:
 *
 *   node web/e2e/real-server/devices-port.check.ts
 *
 * (Node strips the types.) devices-port.spec.ts must run on the real-server
 * fixtures, carry no route mock, and port (or list as a gap or as covered)
 * every case of the mocked Devices Management describe of
 * web/e2e/devices.spec.ts (#2035, epic #1665).
 * Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const port = fs.readFileSync(path.join(import.meta.dirname, 'devices-port.spec.ts'), 'utf8');

assert.ok(port.includes("from './fixtures'"), 'devices-port.spec.ts runs on the real-server fixtures');
for (const banned of [
  'page.route(',
  'context.route(',
  'route.fulfill(',
  'api-mock',
  'dashboard-api-mocks',
  'device-api-mock',
  'auth-setup',
  'test.skip(',
]) {
  assert.ok(!port.includes(banned), `devices-port.spec.ts carries no ${banned}`);
}

const MOCKED: string[] = [
  // Device List
  'should display device table with columns',
  'should display device status badges correctly',
  'should display device type badges correctly',
  'should show empty state when no devices',
  'should show loading state',
  'should filter devices by search query',
  'should clear filters',
  'should display TPM status for devices',
  // Device Details
  'should navigate to device details from list',
  'should display device information',
  'should display TPM info tab',
  'should display attestation history tab',
  'should display certificates tab',
  'should show device not found when device does not exist',
  'should navigate back to devices list',
  // CRUD Operations
  'should open register device dialog',
  'should create a new device',
  'should validate device name is required',
  'should delete a device with confirmation',
  'should cancel delete when dialog is dismissed',
  'should delete device from details page',
  'should toggle device status',
  'refresh attestation enqueues a collection instead of claiming a verdict (#428)',
  // Error States
  'should handle fetch devices error',
  'should handle fetch device details error',
  'should handle create device error',
  'should handle delete device error',
  // Access Control
  'should allow tenant members to view devices',
  'should redirect unauthenticated users to login',
  // Device Details Actions
  'refresh attestation from the details page enqueues and re-reads the report (#428)',
  'should toggle device status from details page',
  'should show empty attestation history message',
  'should show empty certificates message',
  // Device Form Validation
  'should select device type',
  'should fill TPM information',
  'should close dialog on cancel',
];
assert.equal(MOCKED.length, 36, 'the mocked Devices Management describe has 36 cases');

for (const t of MOCKED) {
  assert.ok(port.includes(t), `devices-port.spec.ts ports or lists: ${t}`);
}

console.log('devices-port.check: ok');
