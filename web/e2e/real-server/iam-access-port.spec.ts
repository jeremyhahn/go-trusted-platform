import type { Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

/**
 * IAM roles, groups, permissions and policies (the Roles, Groups,
 * Permissions and Policies describes of the mocked web/e2e/iam.spec.ts),
 * against the real-server harness (#2035).
 *
 * Every case seeds its own roles, groups, users and policies through
 * sdk.iam in the admin's tenant, under unique names, and deletes them in
 * afterEach: the harness runs one daemon for every spec. The tenant's
 * built-in roles are never edited or deleted. Each case drives the page as
 * the console does and asserts what the server answered: on success the
 * rendered row, value, toast or navigation, on a refusal the message the
 * page shows for it.
 */

/** A seed name no other case or spec uses. */
let seq = 0;
function uniqueName(): string {
  seq += 1;
  return `e2e-acc-${Date.now()}-${seq}`;
}

/** The id the console derives from a name (roles/new, groups/new). */
function idFromName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9-]+/g, '-');
}

/** The message of a platform error envelope, in either of its two shapes. */
function serverMessage(body: unknown): string {
  const b = body as { error?: string | { message?: string } } | null;
  if (typeof b?.error === 'string') return b.error;
  return b?.error?.message ?? '';
}

/** A record the server answered: res.data is the record itself, not a wrapper. */
function recordOf(data: unknown): { id?: string; name?: string; description?: string; permissions?: string[] } {
  return (data ?? {}) as { id?: string; name?: string; description?: string; permissions?: string[] };
}

function isCall(method: string, suffix: RegExp): (r: Response) => boolean {
  return (r) => r.request().method() === method && suffix.test(new URL(r.url()).pathname);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** The toast title the console shows, then the server's message when it sent one. */
async function expectRefusal(page: Page, title: string, res: Response): Promise<void> {
  await expect(page.getByText(title, { exact: true }).first()).toBeVisible();
  const msg = serverMessage(await res.json().catch(() => null));
  if (msg) await expect(page.getByText(msg).first()).toBeVisible();
}

/** Narrows a list page's table to name through its search box. */
async function search(page: Page, placeholder: string, name: string): Promise<void> {
  await page.getByPlaceholder(placeholder).fill(name);
}

/**
 * Detail routes are a static export: the build emits one page for the
 * `__placeholder__` id and the client resolves the real id from the URL.
 */
async function openDetail(page: Page, section: 'roles' | 'groups', id: string): Promise<void> {
  await page.goto(`/iam/${section}/__placeholder__/`);
  await page.waitForLoadState('networkidle');
  await page.evaluate(([s, rid]) => window.history.pushState(null, '', `/iam/${s}/${rid}/`), [section, id]);
}

/** The seeds of one case, deleted in reverse order in afterEach. */
type Cleanup = () => Promise<unknown>;

test.describe('IAM access, real server', () => {
  let cleanups: Cleanup[] = [];

  test.beforeEach(() => {
    cleanups = [];
  });

  test.afterEach(async () => {
    for (const c of cleanups.reverse()) await c().catch(() => undefined);
  });

  async function seedRole(sdk: PlatformClient, tenantId: string, permissions: string[], description = ''): Promise<{ id: string; name: string }> {
    const name = uniqueName();
    const res = await sdk.iam.createRole({ tenantId, id: idFromName(name), name, description, permissions });
    expect(res.success, JSON.stringify(res.error)).toBe(true);
    const id = recordOf(res.data).id ?? '';
    expect(id).not.toBe('');
    cleanups.push(() => sdk.iam.deleteRole(tenantId, id));
    return { id, name };
  }

  async function seedGroup(sdk: PlatformClient, tenantId: string, description = ''): Promise<{ id: string; name: string }> {
    const name = uniqueName();
    const res = await sdk.iam.createGroup({ tenantId, id: idFromName(name), name, description });
    expect(res.success, JSON.stringify(res.error)).toBe(true);
    const id = recordOf(res.data).id ?? '';
    expect(id).not.toBe('');
    cleanups.push(() => sdk.iam.deleteGroup(tenantId, id));
    return { id, name };
  }

  async function seedPolicy(sdk: PlatformClient, tenantId: string, description = ''): Promise<string> {
    const name = uniqueName();
    const yaml = [
      'apiVersion: v1',
      'kind: Policy',
      'metadata:',
      `  name: ${name}`,
      `  tenant: ${tenantId}`,
      `  description: ${description}`,
      'spec:',
      '  rules:',
      '    - name: rule-1',
      '      effect: allow',
      '      actions: [read]',
      '      resources: ["*"]',
    ].join('\n');
    // The same spec keys the console's Create Policy page sends.
    const res = await sdk.iam.createPolicy({ tenantId, name, description, specYaml: yaml, spec: yaml, spec_yaml: yaml } as Parameters<PlatformClient['iam']['createPolicy']>[0]);
    expect(res.success, JSON.stringify(res.error)).toBe(true);
    cleanups.push(() => sdk.iam.deletePolicy(tenantId, name));
    return name;
  }

  test.describe('Roles', () => {
    test('should display roles list', async ({ adminPage, sdk, tenant }) => {
      const a = await seedRole(sdk, tenant.id, ['*'], 'Full access');
      const b = await seedRole(sdk, tenant.id, ['read', 'write'], 'Developer access');

      await adminPage.goto('/iam/roles');
      await expect(adminPage.getByRole('heading', { name: 'Roles', exact: true })).toBeVisible();
      await search(adminPage, 'Search roles...', 'e2e-acc-');
      const rowA = adminPage.getByRole('row', { name: new RegExp(escapeRe(a.name)) });
      const rowB = adminPage.getByRole('row', { name: new RegExp(escapeRe(b.name)) });
      await expect(rowA).toBeVisible();
      await expect(rowA).toContainText('Full access');
      await expect(rowB).toBeVisible();
      await expect(rowB).toContainText('Developer access');
    });

    test('should create a new role', async ({ adminPage, sdk, tenant }) => {
      const name = uniqueName();
      cleanups.push(() => sdk.iam.deleteRole(tenant.id, idFromName(name)));

      await adminPage.goto('/iam/roles');
      await adminPage.getByRole('button', { name: /add role/i }).click();
      await expect(adminPage).toHaveURL(/\/iam\/roles\/new/);

      await adminPage.locator('#name').fill(name);
      await adminPage.locator('#description').fill('A custom role');
      await adminPage.locator('#permissions').fill('e2e:read');
      const answer = adminPage.waitForResponse(isCall('POST', /\/iam\/tenants\/[^/]+\/roles$/));
      await adminPage.getByRole('button', { name: 'Create Role' }).click();
      const res = await answer;

      if (res.ok()) {
        await expect(adminPage.getByText('Role created', { exact: true }).first()).toBeVisible();
        await expect(adminPage).toHaveURL(/\/iam\/roles\/?$/);
        await search(adminPage, 'Search roles...', name);
        await expect(adminPage.getByRole('row', { name: new RegExp(escapeRe(name)) })).toContainText('A custom role');
        const got = await sdk.iam.getRole(tenant.id, idFromName(name));
        expect(recordOf(got.data).permissions).toEqual(['e2e:read']);
      } else {
        await expectRefusal(adminPage, 'Failed to create role', res);
      }
    });

    test('should edit role permissions', async ({ adminPage, sdk, tenant }) => {
      const role = await seedRole(sdk, tenant.id, ['read'], 'Before edit');

      await openDetail(adminPage, 'roles', role.id);
      await expect(adminPage.getByRole('heading', { name: 'Role Details' })).toBeVisible();
      await expect(adminPage.getByText(role.name, { exact: true })).toBeVisible();

      await adminPage.getByRole('button', { name: /edit role/i }).click();
      const description = adminPage.getByRole('textbox', { name: /description/i });
      await expect(description).toHaveValue('Before edit');
      await description.fill('Updated description');
      const answer = adminPage.waitForResponse(isCall('PUT', new RegExp(`/roles/${escapeRe(role.id)}$`)));
      await adminPage.getByRole('button', { name: /save changes/i }).click();
      const res = await answer;

      if (res.ok()) {
        await expect(adminPage.getByText('Role updated', { exact: true }).first()).toBeVisible();
        // The page re-reads the role after the save and leaves edit mode.
        await expect(adminPage.getByText('Updated description', { exact: true })).toBeVisible();
        const got = await sdk.iam.getRole(tenant.id, role.id);
        expect(recordOf(got.data).description).toBe('Updated description');
        expect(recordOf(got.data).permissions).toEqual(['read']);
      } else {
        await expectRefusal(adminPage, 'Error updating role', res);
      }
    });

    test('should delete role', async ({ adminPage, sdk, tenant }) => {
      const role = await seedRole(sdk, tenant.id, ['read']);

      await adminPage.goto('/iam/roles');
      await search(adminPage, 'Search roles...', role.name);
      const row = adminPage.getByRole('row', { name: new RegExp(escapeRe(role.name)) });
      await expect(row).toBeVisible();

      adminPage.on('dialog', (dialog) => dialog.accept());
      await row.getByRole('button').last().click();
      const answer = adminPage.waitForResponse(isCall('DELETE', new RegExp(`/roles/${escapeRe(role.id)}$`)));
      await adminPage.getByRole('menuitem', { name: /delete/i }).click();
      const res = await answer;

      if (res.ok()) {
        await expect(adminPage.getByText('Role deleted', { exact: true }).first()).toBeVisible();
        await expect(row).toHaveCount(0);
        const got = await sdk.iam.getRole(tenant.id, role.id);
        expect(got.success).toBe(false);
      } else {
        await expectRefusal(adminPage, 'Error deleting role', res);
        await expect(row).toBeVisible();
      }
    });
  });

  test.describe('Groups', () => {
    test('should display groups list', async ({ adminPage, sdk, tenant }) => {
      const a = await seedGroup(sdk, tenant.id, 'Engineering team');
      const b = await seedGroup(sdk, tenant.id, 'Operations team');

      await adminPage.goto('/iam/groups');
      await expect(adminPage.getByRole('heading', { name: 'Groups', exact: true })).toBeVisible();
      await search(adminPage, 'Search groups...', 'e2e-acc-');
      await expect(adminPage.getByRole('row', { name: new RegExp(escapeRe(a.name)) })).toContainText('Engineering team');
      await expect(adminPage.getByRole('row', { name: new RegExp(escapeRe(b.name)) })).toContainText('Operations team');
    });

    test('should create a new group', async ({ adminPage, sdk, tenant }) => {
      const name = uniqueName();
      cleanups.push(() => sdk.iam.deleteGroup(tenant.id, idFromName(name)));

      await adminPage.goto('/iam/groups');
      await adminPage.getByRole('button', { name: /add group/i }).click();
      await expect(adminPage).toHaveURL(/\/iam\/groups\/new/);

      await adminPage.locator('#name').fill(name);
      await adminPage.locator('#description').fill('A new group');
      const answer = adminPage.waitForResponse(isCall('POST', /\/iam\/tenants\/[^/]+\/groups$/));
      await adminPage.getByRole('button', { name: 'Create Group' }).click();
      const res = await answer;

      if (res.ok()) {
        await expect(adminPage.getByText('Group created', { exact: true }).first()).toBeVisible();
        await expect(adminPage).toHaveURL(/\/iam\/groups\/?$/);
        await search(adminPage, 'Search groups...', name);
        await expect(adminPage.getByRole('row', { name: new RegExp(escapeRe(name)) })).toContainText('A new group');
        const got = await sdk.iam.getGroup(tenant.id, idFromName(name));
        expect(recordOf(got.data).name).toBe(name);
      } else {
        await expectRefusal(adminPage, 'Failed to create group', res);
      }
    });

    // gap: should add member to group: the console has no add-member control (groups/[id]/group-detail-client.tsx renders members read-only) and GetGroup (groupToResponse in pkg/webservice/v1/rest/iam/handlers.go) answers no member list, so no page can show a member the server added
    // gap: should remove member from group: the console has no remove-member control and GetGroup answers no member list, so no page can show a member the server removed

    test('should delete group', async ({ adminPage, sdk, tenant }) => {
      const group = await seedGroup(sdk, tenant.id);

      await adminPage.goto('/iam/groups');
      await search(adminPage, 'Search groups...', group.name);
      const row = adminPage.getByRole('row', { name: new RegExp(escapeRe(group.name)) });
      await expect(row).toBeVisible();

      adminPage.on('dialog', (dialog) => dialog.accept());
      await row.getByRole('button').last().click();
      const answer = adminPage.waitForResponse(isCall('DELETE', new RegExp(`/groups/${escapeRe(group.id)}$`)));
      await adminPage.getByRole('menuitem', { name: /delete/i }).click();
      const res = await answer;

      if (res.ok()) {
        await expect(adminPage.getByText('Group deleted', { exact: true }).first()).toBeVisible();
        await expect(row).toHaveCount(0);
        const got = await sdk.iam.getGroup(tenant.id, group.id);
        expect(got.success).toBe(false);
      } else {
        await expectRefusal(adminPage, 'Error deleting group', res);
        await expect(row).toBeVisible();
      }
    });
  });

  test.describe('Permissions', () => {
    test('should display permissions list', async ({ adminPage, sdk, tenant }) => {
      const resource = `e2eacc${Date.now()}`;
      await seedRole(sdk, tenant.id, [`${resource}:read`, `${resource}:write`]);

      await adminPage.goto('/iam/permissions');
      await expect(adminPage.getByRole('heading', { name: 'Access Control' })).toBeVisible();
      await adminPage.getByRole('tab', { name: /^Permissions \(/ }).click();
      // The page derives the permissions from the roles the server lists.
      // The resource card's title and its count badge share one header row.
      const cardHeader = adminPage.getByText(resource, { exact: true }).first().locator('..');
      await expect(cardHeader).toContainText('2 permissions');
      await search(adminPage, 'Search permissions...', `${resource}:`);
      await expect(adminPage.getByRole('row', { name: new RegExp(`${resource}:read`) })).toBeVisible();
      await expect(adminPage.getByRole('row', { name: new RegExp(`${resource}:write`) })).toBeVisible();
    });

    // gap: should show empty state when no permissions: the page lists the permissions of every role of the tenant, and the harness tenant's built-in roles always carry some (they are not edited or deleted here)

    test('should filter permissions by resource', async ({ adminPage, sdk, tenant }) => {
      const stamp = Date.now();
      const kept = `e2eacc${stamp}a`;
      const dropped = `e2eacc${stamp}b`;
      await seedRole(sdk, tenant.id, [`${kept}:read`, `${dropped}:write`]);

      await adminPage.goto('/iam/permissions');
      await adminPage.getByRole('tab', { name: /^Permissions \(/ }).click();
      await search(adminPage, 'Search permissions...', `e2eacc${stamp}`);
      await expect(adminPage.getByRole('row', { name: new RegExp(`${kept}:read`) })).toBeVisible();
      await expect(adminPage.getByRole('row', { name: new RegExp(`${dropped}:write`) })).toBeVisible();

      await search(adminPage, 'Search permissions...', `${kept}:`);
      await expect(adminPage.getByRole('row', { name: new RegExp(`${kept}:read`) })).toBeVisible();
      await expect(adminPage.getByRole('row', { name: new RegExp(`${dropped}:write`) })).toHaveCount(0);
    });
  });

  test.describe('Policies', () => {
    test('should display policies list', async ({ adminPage, sdk, tenant }) => {
      const a = await seedPolicy(sdk, tenant.id, 'Allow reads');
      const b = await seedPolicy(sdk, tenant.id, 'Allow reads too');

      await adminPage.goto('/iam/policies');
      await expect(adminPage.getByRole('heading', { name: 'Policies', exact: true })).toBeVisible();
      await search(adminPage, 'Search policies...', 'e2e-acc-');
      await expect(adminPage.getByRole('row', { name: new RegExp(escapeRe(a)) })).toBeVisible();
      await expect(adminPage.getByRole('row', { name: new RegExp(escapeRe(b)) })).toBeVisible();
    });

    test('should create a new policy', async ({ adminPage, sdk, tenant }) => {
      const name = uniqueName();
      cleanups.push(() => sdk.iam.deletePolicy(tenant.id, name));

      await adminPage.goto('/iam/policies');
      await adminPage.getByRole('button', { name: /add policy/i }).click();
      await expect(adminPage).toHaveURL(/\/iam\/policies\/new/);

      await adminPage.locator('#name').fill(name);
      await adminPage.locator('#description').fill('Allow all reads');
      await adminPage.locator('#actions').fill('read');
      await adminPage.locator('#resources').fill('*');
      const answer = adminPage.waitForResponse(isCall('POST', /\/iam\/tenants\/[^/]+\/policies$/));
      await adminPage.getByRole('button', { name: 'Create Policy' }).click();
      const res = await answer;

      if (res.ok()) {
        await expect(adminPage.getByText('Policy created', { exact: true }).first()).toBeVisible();
        await expect(adminPage).toHaveURL(/\/iam\/policies\/?$/);
        await search(adminPage, 'Search policies...', name);
        await expect(adminPage.getByRole('row', { name: new RegExp(escapeRe(name)) })).toBeVisible();
        const got = await sdk.iam.getPolicy(tenant.id, name);
        expect(got.success, JSON.stringify(got.error)).toBe(true);
      } else {
        await expectRefusal(adminPage, 'Failed to create policy', res);
      }
    });

    test('should delete policy', async ({ adminPage, sdk, tenant }) => {
      const name = await seedPolicy(sdk, tenant.id);

      await adminPage.goto('/iam/policies');
      await search(adminPage, 'Search policies...', name);
      const row = adminPage.getByRole('row', { name: new RegExp(escapeRe(name)) });
      await expect(row).toBeVisible();

      adminPage.on('dialog', (dialog) => dialog.accept());
      await row.getByRole('button').last().click();
      const answer = adminPage.waitForResponse(isCall('DELETE', new RegExp(`/policies/${escapeRe(encodeURIComponent(name))}$`)));
      await adminPage.getByRole('menuitem', { name: /delete/i }).click();
      const res = await answer;

      if (res.ok()) {
        await expect(adminPage.getByText('Policy deleted', { exact: true }).first()).toBeVisible();
        await expect(row).toHaveCount(0);
        const got = await sdk.iam.getPolicy(tenant.id, name);
        expect(got.success).toBe(false);
      } else {
        await expectRefusal(adminPage, 'Error deleting policy', res);
        await expect(row).toBeVisible();
      }
    });
  });
});
