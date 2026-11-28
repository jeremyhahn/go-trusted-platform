/**
 * Unit check of the invitations port, without a browser or a server:
 *
 *   node web/e2e/real-server/invitations-port.check.ts
 *
 * (Node strips the types.) invitations-port.spec.ts must run on the
 * real-server fixtures, carry no route mock, and port every case of the
 * mocked web/e2e/invitations.spec.ts or list it as a gap or covered.
 * Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const port = fs.readFileSync(path.join(import.meta.dirname, 'invitations-port.spec.ts'), 'utf8');

assert.ok(port.includes("from './fixtures'"), 'invitations-port.spec.ts runs on the real-server fixtures');
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
  assert.ok(!port.includes(banned), `invitations-port.spec.ts carries no ${banned}`);
}

// Every test title of the mocked web/e2e/invitations.spec.ts.
const MOCKED: string[] = [
  'should display invitation form for tenant owners',
  'should display existing invitations in the list',
  'should create a new invitation',
  'should create invitation with admin role',
  'should copy invitation link to clipboard',
  'should revoke an invitation',
  'should show invitation in list after creation',
  'should handle API error when fetching invitations',
  'should handle API error when creating invitation',
  'should handle API error when revoking invitation',
  'should require email input before creating invitation',
  'should navigate back to dashboard',
  'should display access denied for non-owners',
  'should not show invitation form to non-owners',
  'should navigate back to dashboard from access denied page',
  'should redirect to login when not authenticated',
  'should display multiple invitations with different roles',
  'should handle revoking specific invitation from list',
  'should validate email format',
  'should clear form after successful submission',
  'should disable button during submission',
];
for (const t of MOCKED) {
  assert.ok(port.includes(t), `invitations-port.spec.ts ports or lists: ${t}`);
}

// Codex round 4 on #2341: the owner cases run for real.
assert.ok(!port.includes("if (view.kind !== 'owner') return;"), 'the owner cases do not return early off the owner view');
assert.ok(!port.includes('if (!(await expectListed('), 'the owner cases do not return early on a missing seeded row');
assert.ok(port.includes("from './fixtures/wire'"), 'the port reads the unwrapped payload of the answers');
assert.ok(port.includes("toBe('owner')"), 'the owner cases require the owner view');

console.log('invitations-port.check: ok');
