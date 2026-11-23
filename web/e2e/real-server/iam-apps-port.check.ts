/**
 * Unit check of the real-server IAM applications port, without a browser or a server:
 *
 *   node web/e2e/real-server/iam-apps-port.check.ts
 *
 * (Node strips the types.) Every case of the Applications and Access Control
 * describes of the mocked web/e2e/iam.spec.ts must be ported to
 * iam-apps-port.spec.ts against the real server, or listed there as a gap or as
 * covered by another real-server spec. The port must not mock a route.
 * Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const port = fs.readFileSync(path.join(import.meta.dirname, 'iam-apps-port.spec.ts'), 'utf8');

assert.ok(port.includes("from './fixtures'"), "iam-apps-port.spec.ts imports the harness from './fixtures'");

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
  assert.ok(!port.includes(banned), `iam-apps-port.spec.ts does not use ${banned}`);
}

const MOCKED: string[] = [
  'should display applications list',
  'should show statistics cards',
  'should open register application dialog',
  'should show empty state when no applications',
  'should show application row actions',
  'should navigate to application details on view',
  'should delete application with confirmation',
  'should cancel delete when confirmation is declined',
  'should select multiple applications with checkboxes',
  'should handle API errors gracefully',
  'should handle delete API error',
  'should search/filter applications',
  'should display grant types badges correctly',
  'should handle row click navigation to details',
  'should show loading state',
  'should show toast when rotate secret is clicked',
  'should display client ID truncated in table',
  'should display redirect URIs count',
  'should navigate to edit on edit action',
  'should allow tenant members to view users',
  'should redirect unauthenticated users to login',
];

for (const t of MOCKED) {
  assert.ok(port.includes(t), `iam-apps-port.spec.ts ports or lists: ${t}`);
}

console.log('iam-apps-port.check: ok');
