/**
 * Unit check of the admin workspace real-server spec, without a browser or a
 * server (#2067, epic #1665):
 *
 *   node web/e2e/real-server/admin-workspace.check.ts
 *
 * (Node strips the types.) admin-workspace.spec.ts must drive /admin/tenant
 * against the real server: no page.route mocks, no api-mock, and it compares
 * the page with the server's own answer to GET /api/v1/tenants/{id}.
 * Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const specPath = path.join(import.meta.dirname, 'admin-workspace.spec.ts');
assert.ok(fs.existsSync(specPath), 'admin-workspace.spec.ts exists next to this check');

const spec = fs.readFileSync(specPath, 'utf8');
assert.ok(!spec.includes('page.route('), 'admin-workspace.spec.ts mocks no route (page.route)');
assert.ok(!spec.includes('api-mock'), 'admin-workspace.spec.ts does not use api-mock');
assert.ok(spec.includes(`goto('/admin/tenant')`), "admin-workspace.spec.ts goes to '/admin/tenant'");
assert.match(spec, /waitForResponse\(/, 'admin-workspace.spec.ts waits on the page response');
assert.ok(
  spec.includes('/api/v1/tenants/'),
  'admin-workspace.spec.ts waits on the GET of /api/v1/tenants/{id}',
);

console.log('admin-workspace.check: ok');
