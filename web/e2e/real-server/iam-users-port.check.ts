/**
 * Unit check of the IAM users real-server port, without a browser or a server:
 *
 *   node web/e2e/real-server/iam-users-port.check.ts
 *
 * (Node strips the types.) Every case of the Users List, User CRUD, User
 * Details and Error States describes of the mocked web/e2e/iam.spec.ts must be
 * ported to iam-users-port.spec.ts, or listed there as a `// gap:` or
 * `// covered:` line, and the port must run on the real-server fixtures with
 * no route mock. Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const port = fs.readFileSync(path.join(import.meta.dirname, 'iam-users-port.spec.ts'), 'utf8');

assert.ok(port.includes("from './fixtures'"), 'iam-users-port.spec.ts runs on the real-server fixtures');
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
  assert.ok(!port.includes(banned), `iam-users-port.spec.ts does not use ${banned}`);
}

const MOCKED: string[] = [
  // Users List
  'should display user table with columns',
  'should display user status badges correctly',
  'should show empty state when no users',
  'should show loading state',
  'should filter users by search query',
  'should filter users by status',
  'should support pagination',
  // User CRUD
  'should open create user dialog',
  'should create a new user',
  'should validate required fields',
  'should edit user details',
  'should delete user with confirmation',
  'should disable/enable user',
  // User Details
  'should navigate to user details from list',
  'should display user information',
  'should show assigned roles',
  'should show group memberships',
  'should show user not found when user does not exist',
  'should navigate back to users list',
  // Error States
  'should handle fetch users error',
  'should handle fetch roles error',
  'should handle fetch groups error',
  'should handle create user error',
  'should handle delete user error',
  'should handle permission denied',
];
assert.equal(MOCKED.length, 25, 'the 25 mocked IAM users and error-state titles');

for (const t of MOCKED) {
  assert.ok(port.includes(t), `iam-users-port.spec.ts ports or lists: ${t}`);
}

// Codex round 4 P1: Response.json() is the raw envelope; the user is under payload.
assert.ok(port.includes('unwrapPayload('), 'iam-users-port.spec.ts unwraps raw answers with unwrapPayload');
assert.ok(port.includes("from './fixtures/wire'"), "iam-users-port.spec.ts imports unwrapPayload from './fixtures/wire'");
assert.ok(!port.includes('userOf(await res.json())'), 'iam-users-port.spec.ts reads no user from the raw envelope');

console.log('iam-users-port.check: ok');
