/**
 * Unit check of the real-server Device Profiles port, without a browser or a server:
 *
 *   node web/e2e/real-server/device-profiles-port.check.ts
 *
 * (Node strips the types.) The port must run on the real-server fixtures, use
 * no route mock, and port or list (as a gap or as covered elsewhere) every case
 * of the mocked Device Profiles describe of web/e2e/devices.spec.ts.
 * Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const port = fs.readFileSync(path.join(import.meta.dirname, 'device-profiles-port.spec.ts'), 'utf8');

assert.ok(port.includes("from './fixtures'"), 'device-profiles-port.spec.ts imports the real-server fixtures');
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
  assert.ok(!port.includes(banned), `device-profiles-port.spec.ts does not use ${banned}`);
}

const MOCKED: string[] = [
  // Profile List
  'should display profiles list',
  'should show statistics cards',
  'should open create profile dialog',
  'should create a new profile',
  'should filter profiles by role',
  'should search profiles',
  'should delete profile with confirmation',
  'should duplicate profile',
  'should handle API errors gracefully',
  'should show empty state when no profiles',
  // Profile Actions
  'should navigate to profile details',
  'should navigate to edit profile',
  'should cancel delete when dialog is dismissed',
  'should display network configurations in table',
  'should render a phase key outside the three defaults',
  'should mark the phase a selector names, not the default key',
  'should show no networks message when profile has no networks',
  'should show role badges correctly',
  'should handle create profile error',
  'should handle delete profile error',
  'should refresh profiles list',
  'should clear filters',
  'should show loading state',
  'should close create dialog on cancel',
  // Access Control
  'should allow tenant members to view profiles',
  'should redirect unauthenticated users to login',
];
assert.equal(MOCKED.length, 26, 'the mocked Device Profiles describe has 26 cases');
for (const t of MOCKED) {
  assert.ok(port.includes(t), `device-profiles-port.spec.ts ports or lists: ${t}`);
}

// Codex round 4 P1: Response.json() is the raw envelope; the profile is under payload.
assert.ok(port.includes('unwrapPayload('), 'device-profiles-port.spec.ts unwraps raw answers with unwrapPayload');
assert.ok(port.includes("from './fixtures/wire'"), "device-profiles-port.spec.ts imports unwrapPayload from './fixtures/wire'");
assert.ok(!port.includes('isRecord(body) && body.name'), 'device-profiles-port.spec.ts reads no profile from the raw envelope');

console.log('device-profiles-port.check: ok');
