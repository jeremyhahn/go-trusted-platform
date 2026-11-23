/**
 * Unit check of the Device vTPM real-server port, without a browser or a server:
 *
 *   node web/e2e/real-server/device-vtpm-port.check.ts
 *
 * (Node strips the types.) device-vtpm-port.spec.ts must run on the
 * real-server fixtures with no route mock, and every case of the mocked
 * Device vTPM describe in web/e2e/devices.spec.ts must be ported under its
 * title or listed as a `// gap:` or `// covered:` line naming it.
 * Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const port = fs.readFileSync(path.join(import.meta.dirname, 'device-vtpm-port.spec.ts'), 'utf8');

assert.ok(port.includes("from './fixtures'"), 'device-vtpm-port.spec.ts runs on the real-server fixtures');
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
  assert.ok(!port.includes(banned), `device-vtpm-port.spec.ts does not use ${banned}`);
}

const MOCKED: string[] = [
  // vTPM List
  'should display vTPM page header and description',
  'should display vTPM table with columns',
  'should display vTPM state badges correctly',
  'should show empty state when no vTPM instances',
  'should show loading state',
  'should filter vTPM instances by search query',
  'should filter vTPM instances by VM ID',
  'should filter vTPM instances by state',
  'should clear filters',
  // Create vTPM
  'should open create vTPM dialog',
  'should display all form fields in create dialog',
  'should create a new vTPM instance',
  'should validate vTPM name is required',
  'should validate VM ID is required',
  'should validate VM name is required',
  'should close create dialog on cancel',
  'should close create dialog with Escape key',
  // vTPM Actions
  'should open actions menu for vTPM',
  'should navigate to vTPM details from actions menu',
  'should navigate to seal data action',
  'should show suspend info toast for active vTPM',
  'should navigate to migrate action',
  'should delete vTPM with confirmation',
  'should cancel delete when dialog is dismissed',
  // Error States
  'should handle fetch vTPM error',
  'should handle create vTPM error',
  'should handle delete vTPM error',
  // Access Control
  'should allow tenant members to view vTPM instances',
  'should redirect unauthenticated users to login',
  // PCR Profile Display
  'should display PCR profile badge for vTPM',
  // Date Formatting
  'should display formatted creation date',
  // Multiple vTPM Instances
  'should display multiple vTPM instances correctly',
  'should handle actions on specific vTPM in list',
  // Form Fields
  'should fill PCR profile field',
  'should fill description field',
  'should show form descriptions for each field',
];
assert.equal(MOCKED.length, 36, 'the mocked Device vTPM describe has 36 cases');
for (const t of MOCKED) {
  assert.ok(port.includes(t), `device-vtpm-port.spec.ts ports or lists: ${t}`);
}

console.log('device-vtpm-port.check: ok');
