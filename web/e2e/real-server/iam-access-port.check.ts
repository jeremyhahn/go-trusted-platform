/**
 * Unit check of the IAM roles, groups, permissions and policies port, without
 * a browser or a server:
 *
 *   node web/e2e/real-server/iam-access-port.check.ts
 *
 * (Node strips the types.) iam-access-port.spec.ts must run on the
 * real-server fixtures with no route mock, and must port every case of the
 * Roles, Groups, Permissions and Policies describes of the mocked
 * web/e2e/iam.spec.ts, or list it as a `// gap:` or `// covered:` line.
 * Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const port = fs.readFileSync(path.join(import.meta.dirname, 'iam-access-port.spec.ts'), 'utf8');

assert.ok(port.includes("from './fixtures'"), 'iam-access-port.spec.ts runs on the real-server fixtures');

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
  assert.ok(!port.includes(f), `iam-access-port.spec.ts does not use ${f}`);
}

const MOCKED: string[] = [
  // Roles
  'should display roles list',
  'should create a new role',
  'should edit role permissions',
  'should delete role',
  // Groups
  'should display groups list',
  'should create a new group',
  'should add member to group',
  'should remove member from group',
  'should delete group',
  // Permissions
  'should display permissions list',
  'should show empty state when no permissions',
  'should filter permissions by resource',
  // Policies
  'should display policies list',
  'should create a new policy',
  'should delete policy',
];
for (const t of MOCKED) {
  assert.ok(port.includes(t), `iam-access-port.spec.ts ports or lists: ${t}`);
}

console.log('iam-access-port.check: ok');
