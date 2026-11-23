/**
 * Unit check of the IAM API credentials port, without a browser or a server:
 *
 *   node web/e2e/real-server/iam-tokens-port.check.ts
 *
 * (Node strips the types.) iam-tokens-port.spec.ts must run on the real-server
 * fixtures, carry no route mock, and port (or list as a gap or as covered)
 * every case of the API Credentials / Tokens describe of the mocked
 * web/e2e/iam.spec.ts. Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const port = fs.readFileSync(path.join(import.meta.dirname, 'iam-tokens-port.spec.ts'), 'utf8');

assert.ok(port.includes("from './fixtures'"), 'iam-tokens-port.spec.ts runs on the real-server fixtures');
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
  assert.ok(!port.includes(banned), `iam-tokens-port.spec.ts carries no ${banned}`);
}

const MOCKED: string[] = [
  'should display API credentials list',
  'should show statistics cards',
  'should open register application dialog',
  'should register a new application and show secret',
  'should validate application name is required',
  'should rotate application secret',
  'should delete application with confirmation',
  'should cancel delete when confirmation is rejected',
  'should handle bulk delete',
  'should handle API errors gracefully',
  'should handle register application error',
  'should handle delete error',
  'should handle rotate secret error',
  'should search credentials',
  'should show empty state when no applications',
  'should display grant types badges',
  'should show loading state',
  'should copy secret to clipboard',
  'should show OAuth info alert',
];
assert.equal(MOCKED.length, 19, 'the API Credentials / Tokens describe has 19 cases');
for (const t of MOCKED) {
  assert.ok(port.includes(t), `iam-tokens-port.spec.ts ports or lists: ${t}`);
}

console.log('iam-tokens-port.check: ok');
