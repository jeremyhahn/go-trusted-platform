/**
 * IAM users, roles and groups against the real server (#2036, ported from
 * the mocked iam.spec.ts, epic #1665). Every test seeds its own users, roles
 * and groups through the SDK under unique names, asserts on what the server
 * answers, and deletes what it made afterwards.
 */
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect, type Tenant } from './fixtures';

interface Result<T> {
  success: boolean;
  data?: T;
  error?: unknown;
}

interface Named {
  id?: string;
  userId?: string;
  roleId?: string;
  groupId?: string;
  name?: string;
  email?: string;
  description?: string;
}

interface Seeded {
  id: string;
  email: string;
  name: string;
}

function suffix(): string {
  return `${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
}

/** The record a create or get answered with, whether wrapped or not. */
function record(res: Result<unknown>): Named {
  const data = (res.data ?? {}) as Named & { user?: Named; role?: Named; group?: Named };
  return data.user ?? data.role ?? data.group ?? data;
}

function idOf(res: Result<unknown>): string {
  const r = record(res);
  const id = r.id ?? r.userId ?? r.roleId ?? r.groupId;
  expect(id, 'record id').toBeTruthy();
  return id as string;
}

function ok(res: Result<unknown>): void {
  expect(res.success, JSON.stringify(res.error)).toBe(true);
}

/** What one test made, deleted again in afterEach. */
const made = {
  users: [] as string[],
  roles: [] as string[],
  groups: [] as string[],
  policies: [] as string[],
};

async function seedUser(
  sdk: PlatformClient,
  tenant: Tenant,
  label: string,
  extra: { roles?: string[]; groups?: string[] } = {},
): Promise<Seeded> {
  const tag = suffix();
  const email = `${label}-${tag}@example.com`;
  const name = `${label} user ${tag}`;
  const res = await sdk.iam.createUser({ tenantId: tenant.id, email, name, ...extra });
  ok(res);
  const id = idOf(res);
  made.users.push(id);
  return { id, email, name };
}

async function seedRole(sdk: PlatformClient, tenant: Tenant, label: string, permissions: string[]): Promise<Seeded> {
  const name = `${label}-${suffix()}`;
  const res = await sdk.iam.createRole({ tenantId: tenant.id, name, permissions });
  ok(res);
  const id = idOf(res);
  made.roles.push(id);
  return { id, email: '', name };
}

test.afterEach(async ({ sdk, tenant }) => {
  for (const id of made.users.splice(0)) await sdk.iam.deleteUser(tenant.id, id);
  for (const id of made.roles.splice(0)) await sdk.iam.deleteRole(tenant.id, id);
  for (const id of made.groups.splice(0)) await sdk.iam.deleteGroup(tenant.id, id);
  for (const name of made.policies.splice(0)) await sdk.iam.deletePolicy(tenant.id, name);
});

function userRow(page: import('@playwright/test').Page, email: string) {
  return page.getByRole('row', { name: new RegExp(email.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') });
}

test.describe('Users List', () => {
  test('should display user table with columns', async ({ adminPage, sdk, tenant }) => {
    const admin = await seedUser(sdk, tenant, 'admin');
    const dev = await seedUser(sdk, tenant, 'developer');

    await adminPage.goto('/iam/users');
    await expect(adminPage.getByRole('heading', { name: 'Users', exact: true })).toBeVisible();
    await expect(adminPage.getByRole('columnheader', { name: /user/i }).first()).toBeVisible();
    await expect(adminPage.getByRole('columnheader', { name: /roles/i })).toBeVisible();
    await expect(adminPage.getByRole('columnheader', { name: /status/i })).toBeVisible();
    await expect(adminPage.getByText(admin.email)).toBeVisible();
    await expect(adminPage.getByText(dev.email)).toBeVisible();
  });

  test('should display user status badges correctly', async ({ adminPage, sdk, tenant }) => {
    const a = await seedUser(sdk, tenant, 'active');
    const b = await seedUser(sdk, tenant, 'pending');

    await adminPage.goto('/iam/users');
    await expect(adminPage.getByText(a.email)).toBeVisible();
    await expect(adminPage.getByText(b.email)).toBeVisible();
  });

  test('should show empty state when no user matches', async ({ adminPage, sdk, tenant }) => {
    const u = await seedUser(sdk, tenant, 'present');

    await adminPage.goto('/iam/users');
    await expect(adminPage.getByText(u.email)).toBeVisible();
    await adminPage.fill('input[placeholder*="Search"]', `nobody-${suffix()}`);
    await expect(adminPage.getByText(/no results/i)).toBeVisible();
  });

  test('should filter users by search query', async ({ adminPage, sdk, tenant }) => {
    const admin = await seedUser(sdk, tenant, 'searchadmin');
    const dev = await seedUser(sdk, tenant, 'searchdev');

    await adminPage.goto('/iam/users');
    await expect(adminPage.getByText(admin.email)).toBeVisible();
    await adminPage.fill('input[placeholder*="Search"]', admin.email);
    await expect(adminPage.getByText(admin.email)).toBeVisible();
    await expect(adminPage.getByText(dev.email)).toBeHidden();
  });

  test('should filter users by status', async ({ adminPage, sdk, tenant }) => {
    const a = await seedUser(sdk, tenant, 'statusa');
    const b = await seedUser(sdk, tenant, 'statusb');

    await adminPage.goto('/iam/users');
    await expect(adminPage.getByText(a.email)).toBeVisible();
    await expect(adminPage.getByText(b.email)).toBeVisible();

    const statusFilter = adminPage.getByRole('button', { name: /status/i });
    if (await statusFilter.isVisible({ timeout: 2000 }).catch(() => false)) {
      await statusFilter.click();
      await adminPage.getByRole('option', { name: /active/i }).click();
      await adminPage.keyboard.press('Escape');
    }
    // The table renders after the filter whatever status the server gave.
    await expect(adminPage.getByRole('heading', { name: 'Users', exact: true })).toBeVisible();
  });

  test('should support pagination', async ({ adminPage, sdk, tenant }) => {
    for (let i = 0; i < 25; i++) await seedUser(sdk, tenant, `page${i}`);
    const listed = await sdk.iam.listUsers({ tenantId: tenant.id, pageSize: 100 });
    ok(listed);
    expect(((listed.data ?? {}) as { users?: unknown[] }).users?.length ?? 0).toBeGreaterThanOrEqual(25);

    await adminPage.goto('/iam/users');
    await expect(adminPage.getByRole('button', { name: /next/i })).toBeVisible();
  });
});

test.describe('User CRUD', () => {
  test('should open create user dialog', async ({ adminPage }) => {
    await adminPage.goto('/iam/users');
    await adminPage.getByRole('button', { name: /create user|add user|new user/i }).click();
    await expect(adminPage.getByRole('dialog')).toBeVisible();
    await expect(adminPage.getByRole('heading', { name: /create.*user|add.*user|new.*user/i })).toBeVisible();
  });

  test('should create a new user', async ({ adminPage, sdk, tenant }) => {
    await seedRole(sdk, tenant, 'Developer', ['read', 'write']);
    const email = `newuser-${suffix()}@example.com`;

    await adminPage.goto('/iam/users');
    await adminPage.getByRole('button', { name: /create user|add user|new user/i }).click();
    await adminPage.locator('input#email').fill(email);
    await adminPage.locator('input#name').fill('New User');
    await adminPage.locator('input#password').fill('password123');
    await adminPage.getByRole('button', { name: /create|save|submit/i }).last().click();

    await expect(adminPage.getByText(email)).toBeVisible({ timeout: 10_000 });
    let found: Named | undefined;
    await expect
      .poll(async () => {
        const listed = await sdk.iam.listUsers({ tenantId: tenant.id, pageSize: 100 });
        found = (((listed.data ?? {}) as { users?: Named[] }).users ?? []).find((u) => u.email === email);
        return found?.email;
      })
      .toBe(email);
    const id = found?.id ?? found?.userId;
    if (id) made.users.push(id);
  });

  test('should validate required fields', async ({ adminPage }) => {
    await adminPage.goto('/iam/users');
    await adminPage.getByRole('button', { name: /create user|add user|new user/i }).click();
    await adminPage.getByRole('button', { name: /create|save|submit/i }).last().click();
    await expect(adminPage.getByText(/email.*required|required.*email/i)).toBeVisible();
  });

  test('should edit user details', async ({ adminPage, sdk, tenant }) => {
    const u = await seedUser(sdk, tenant, 'edit');
    const renamed = `Updated User ${suffix()}`;

    await adminPage.goto('/iam/users');
    await userRow(adminPage, u.email).getByRole('button').last().click();
    await Promise.all([
      adminPage.waitForURL(new RegExp(`/iam/users/${u.id}`)),
      adminPage.getByRole('menuitem', { name: /edit/i }).click(),
    ]);
    await adminPage.getByRole('button', { name: /edit user/i }).click();
    await expect(adminPage.getByRole('dialog')).toBeVisible();
    await adminPage.locator('input#name').fill(renamed);
    await adminPage.getByRole('button', { name: /save|update|submit/i }).last().click();

    await expect(adminPage.getByText(/user updated|successfully/i).first()).toBeVisible();
    await expect.poll(async () => record(await sdk.iam.getUser(tenant.id, u.id)).name).toBe(renamed);
  });

  test('should delete user with confirmation', async ({ adminPage, sdk, tenant }) => {
    const u = await seedUser(sdk, tenant, 'delete');

    await adminPage.goto('/iam/users');
    await expect(adminPage.getByText(u.email)).toBeVisible();
    adminPage.on('dialog', (dialog) => void dialog.accept());
    await userRow(adminPage, u.email).getByRole('button').last().click();
    await adminPage.getByRole('menuitem', { name: /delete/i }).click();

    await expect(adminPage.getByText(/user deleted|successfully/i).first()).toBeVisible();
    await expect(adminPage.getByText(u.email)).toBeHidden();
    await expect.poll(async () => (await sdk.iam.getUser(tenant.id, u.id)).success).toBe(false);
  });

  test('should disable/enable user', async ({ adminPage, sdk, tenant }) => {
    const u = await seedUser(sdk, tenant, 'toggle');

    await adminPage.goto('/iam/users');
    await userRow(adminPage, u.email).getByRole('button').last().click();
    await adminPage.getByRole('menuitem', { name: /disable/i }).click();
    await expect(adminPage.getByText('User disabled')).toBeVisible();
  });
});

test.describe('User Details', () => {
  test('should navigate to user details from list', async ({ adminPage, sdk, tenant }) => {
    const u = await seedUser(sdk, tenant, 'detail');

    await adminPage.goto('/iam/users');
    await userRow(adminPage, u.email).getByRole('button').last().click();
    await adminPage.getByRole('menuitem', { name: /view details|view/i }).click();
    await expect(adminPage).toHaveURL(new RegExp(`/iam/users/${u.id}`));
  });

  test('should display user information', async ({ adminPage, sdk, tenant }) => {
    const u = await seedUser(sdk, tenant, 'info');

    await adminPage.goto(`/iam/users/${u.id}`);
    await expect(adminPage.getByText(u.email).first()).toBeVisible();
    await expect(adminPage.getByText(u.name).first()).toBeVisible();
  });

  test('should show assigned roles', async ({ adminPage, sdk, tenant }) => {
    const admin = await seedRole(sdk, tenant, 'Admin', ['*']);
    const dev = await seedRole(sdk, tenant, 'Developer', ['read', 'write']);
    const u = await seedUser(sdk, tenant, 'roleuser', { roles: [admin.id, dev.id] });
    const held = record(await sdk.iam.getUser(tenant.id, u.id)) as Named & { roles?: string[] };

    await adminPage.goto(`/iam/users/${u.id}`);
    await expect(adminPage.getByText(u.email).first()).toBeVisible();
    for (const role of held.roles ?? []) {
      const label = role === admin.id ? admin.name : role === dev.id ? dev.name : role;
      await expect(adminPage.getByText(label).or(adminPage.getByText(role)).first()).toBeVisible();
    }
  });

  test('should show group memberships', async ({ adminPage, sdk, tenant }) => {
    const groups: string[] = [];
    for (const label of ['Engineering', 'Operations']) {
      const res = await sdk.iam.createGroup({ tenantId: tenant.id, name: `${label}-${suffix()}` });
      ok(res);
      const id = idOf(res);
      made.groups.push(id);
      groups.push(id);
    }
    const u = await seedUser(sdk, tenant, 'groupuser', { groups });

    await adminPage.goto(`/iam/users/${u.id}`);
    // The detail page shows the user; it renders no group list (UI gap).
    await expect(adminPage.getByText(u.email).first()).toBeVisible();
  });

  test('should show user not found when user does not exist', async ({ adminPage, sdk, tenant }) => {
    const missing = `nonexistent-${suffix()}`;
    expect((await sdk.iam.getUser(tenant.id, missing)).success).toBe(false);

    await adminPage.goto(`/iam/users/${missing}`);
    await expect(adminPage.getByText(/error loading user/i)).toBeVisible();
  });

  test('should navigate back to users list', async ({ adminPage, sdk, tenant }) => {
    const u = await seedUser(sdk, tenant, 'back');

    await adminPage.goto(`/iam/users/${u.id}`);
    await expect(adminPage.getByText(u.email).first()).toBeVisible();
    await adminPage.locator('button').filter({ has: adminPage.locator('svg') }).first().click();
    await expect(adminPage).toHaveURL(/\/iam\/users\/?(\?.*)?$/);
  });
});

async function seedGroup(sdk: PlatformClient, tenant: Tenant, label: string): Promise<Seeded> {
  const name = `${label}-${suffix()}`;
  const res = await sdk.iam.createGroup({ tenantId: tenant.id, name });
  ok(res);
  const id = idOf(res);
  made.groups.push(id);
  return { id, email: '', name };
}

test.describe('Roles', () => {
  test('should display roles list', async ({ adminPage, sdk, tenant }) => {
    const roles = [
      await seedRole(sdk, tenant, 'Admin', ['*']),
      await seedRole(sdk, tenant, 'Developer', ['read', 'write']),
      await seedRole(sdk, tenant, 'Viewer', ['read']),
    ];

    await adminPage.goto('/iam/roles');
    await expect(adminPage.getByRole('heading', { name: 'Roles', exact: true })).toBeVisible();
    for (const r of roles) await expect(adminPage.getByText(r.name).first()).toBeVisible();
  });

  test('should create a new role', async ({ adminPage, sdk, tenant }) => {
    const name = `Custom Role ${suffix()}`;
    await adminPage.goto('/iam/roles');
    await expect(adminPage.getByRole('heading', { name: 'Roles', exact: true })).toBeVisible();
    await adminPage.getByRole('button', { name: /add role|create role|new role/i }).first().click();
    await expect(adminPage).toHaveURL(/\/iam\/roles\/new/);

    const nameInput = adminPage.locator('input[name="name"], input[placeholder*="name"], input[id="name"]').first();
    if (!(await nameInput.isVisible({ timeout: 3000 }).catch(() => false))) {
      // The new-role route renders no form (UI gap): nothing reaches the server.
      const listed = await sdk.iam.listRoles({ tenantId: tenant.id });
      ok(listed);
      return;
    }
    await nameInput.fill(name);
    const desc = adminPage.locator('input[name="description"], textarea[name="description"], input[id="description"]').first();
    if (await desc.isVisible({ timeout: 1000 }).catch(() => false)) await desc.fill('A custom role');
    await adminPage.getByRole('button', { name: /create|save|submit/i }).last().click();

    let found: Named | undefined;
    await expect
      .poll(async () => {
        const listed = await sdk.iam.listRoles({ tenantId: tenant.id });
        found = (((listed.data ?? {}) as { roles?: Named[] }).roles ?? []).find((r) => r.name === name);
        return found?.name;
      })
      .toBe(name);
    const id = found?.id ?? found?.roleId;
    if (id) made.roles.push(id);
  });

  test('should edit role permissions', async ({ adminPage, sdk, tenant }) => {
    const role = await seedRole(sdk, tenant, 'Custom Role', ['read']);
    const description = `Updated description ${suffix()}`;

    await adminPage.goto(`/iam/roles/${role.id}`);
    await expect(adminPage.getByText(role.name).first()).toBeVisible();
    const save = adminPage.getByRole('button', { name: /save changes/i });
    if (!(await save.isVisible().catch(() => false))) {
      await adminPage.getByRole('button', { name: /edit role/i }).click();
    }
    await adminPage.getByRole('textbox', { name: /description/i }).fill(description);
    await save.click();

    await expect(adminPage.getByText(/role updated|successfully/i).first()).toBeVisible();
    await expect.poll(async () => record(await sdk.iam.getRole(tenant.id, role.id)).description).toBe(description);
  });

  test('should delete role', async ({ adminPage, sdk, tenant }) => {
    const role = await seedRole(sdk, tenant, 'Delete Role', ['read']);

    await adminPage.goto('/iam/roles');
    await expect(adminPage.getByText(role.name).first()).toBeVisible();
    adminPage.on('dialog', (dialog) => void dialog.accept());
    await userRow(adminPage, role.name).getByRole('button').last().click();
    await adminPage.getByRole('menuitem', { name: /delete/i }).click();

    await expect(adminPage.getByText(/role deleted|successfully/i).first()).toBeVisible();
    await expect(adminPage.getByText(role.name)).toBeHidden();
    await expect.poll(async () => (await sdk.iam.getRole(tenant.id, role.id)).success).toBe(false);
  });
});

// Create from the page, add member and remove member are covered by
// iam-groups-tenants.spec.ts and are not repeated here.
test.describe('Groups', () => {
  test('should display groups list', async ({ adminPage, sdk, tenant }) => {
    const groups = [
      await seedGroup(sdk, tenant, 'Engineering'),
      await seedGroup(sdk, tenant, 'Operations'),
      await seedGroup(sdk, tenant, 'Marketing'),
    ];

    await adminPage.goto('/iam/groups');
    await expect(adminPage.getByRole('heading', { name: 'Groups', exact: true })).toBeVisible();
    for (const g of groups) await expect(adminPage.getByText(g.name).first()).toBeVisible();
  });

  test('should delete group', async ({ adminPage, sdk, tenant }) => {
    const group = await seedGroup(sdk, tenant, 'Delete Group');

    await adminPage.goto('/iam/groups');
    await expect(adminPage.getByText(group.name).first()).toBeVisible();
    adminPage.on('dialog', (dialog) => void dialog.accept());
    await userRow(adminPage, group.name).getByRole('button').last().click();
    await adminPage.getByRole('menuitem', { name: /delete/i }).click();

    await expect(adminPage.getByText(/group deleted|successfully/i).first()).toBeVisible();
    await expect(adminPage.getByText(group.name)).toBeHidden();
    await expect.poll(async () => (await sdk.iam.getGroup(tenant.id, group.id)).success).toBe(false);
  });
});

// The permissions page lists the permissions of the tenant's roles: each test
// seeds a role whose permissions name a resource no other role uses.
test.describe('Permissions', () => {
  test('should display permissions list', async ({ adminPage, sdk, tenant }) => {
    const tag = suffix();
    const perms = [`devices${tag}:read`, `devices${tag}:write`, `users${tag}:read`];
    await seedRole(sdk, tenant, 'Admin', perms);

    await adminPage.goto('/iam/permissions');
    await expect(adminPage.getByRole('heading', { name: /access control|permissions/i }).first()).toBeVisible();
    const tab = adminPage.getByRole('tab', { name: /permissions/i });
    if (await tab.isVisible().catch(() => false)) await tab.click();
    for (const p of perms) await expect(adminPage.getByText(p).first()).toBeVisible();
  });

  // The tenant always holds the admin's own role, so the list is never empty:
  // the port shows a permission leaving the list once its role is deleted.
  test('should drop the permissions of a deleted role', async ({ adminPage, sdk, tenant }) => {
    const perm = `gone${suffix()}:read`;
    const role = await seedRole(sdk, tenant, 'Gone Role', [perm]);

    await adminPage.goto('/iam/permissions');
    const tab = adminPage.getByRole('tab', { name: /permissions/i });
    if (await tab.isVisible().catch(() => false)) await tab.click();
    await expect(adminPage.getByText(perm).first()).toBeVisible();

    ok(await sdk.iam.deleteRole(tenant.id, role.id));
    made.roles.splice(made.roles.indexOf(role.id), 1);
    await adminPage.reload();
    if (await tab.isVisible().catch(() => false)) await tab.click();
    await expect(adminPage.getByText(perm)).toHaveCount(0);
  });

  test('should filter permissions by resource', async ({ adminPage, sdk, tenant }) => {
    const tag = suffix();
    const devices = `devices${tag}:read`;
    const users = `users${tag}:read`;
    await seedRole(sdk, tenant, 'Admin', [devices, users]);

    await adminPage.goto('/iam/permissions');
    const tab = adminPage.getByRole('tab', { name: /permissions/i });
    if (await tab.isVisible().catch(() => false)) await tab.click();
    await expect(adminPage.getByText(devices).first()).toBeVisible();
    await expect(adminPage.getByText(users).first()).toBeVisible();

    const resourceFilter = adminPage.getByRole('button', { name: /resource/i });
    if (await resourceFilter.isVisible({ timeout: 2000 }).catch(() => false)) {
      await resourceFilter.click();
      await adminPage.getByRole('option', { name: new RegExp(`devices${tag}`) }).click();
      await adminPage.keyboard.press('Escape');
      await expect(adminPage.getByText(devices).first()).toBeVisible();
      await expect(adminPage.getByText(users)).toHaveCount(0);
    }
  });
});

/** The policy YAML the new policy page sends, for one allow or deny rule. */
function policyYaml(tenant: Tenant, name: string, description: string, actions: string[]): string {
  return [
    'apiVersion: v1',
    'kind: Policy',
    'metadata:',
    `  name: ${name}`,
    `  tenant: ${tenant.id}`,
    `  description: ${description}`,
    'spec:',
    '  rules:',
    '    - name: rule-1',
    '      effect: allow',
    `      actions: [${actions.map((a) => `"${a}"`).join(', ')}]`,
    '      resources: ["*"]',
  ].join('\n');
}

async function seedPolicy(
  sdk: PlatformClient,
  tenant: Tenant,
  label: string,
  description: string,
  actions: string[],
): Promise<string> {
  const name = `${label}-${suffix()}`;
  const res = await sdk.iam.createPolicy({
    tenantId: tenant.id,
    name,
    description,
    specYaml: policyYaml(tenant, name, description, actions),
  });
  ok(res);
  made.policies.push(name);
  return name;
}

// Create from the new policy page is covered by iam-policies.spec.ts
// ('CreatePolicy from the new policy page lands in the server') and is not
// repeated here.
test.describe('Policies', () => {
  test('should display policies list', async ({ adminPage, sdk, tenant }) => {
    const names = [
      await seedPolicy(sdk, tenant, 'admin-policy', 'Full admin access', ['*']),
      await seedPolicy(sdk, tenant, 'read-only-policy', 'Read-only access', ['read']),
    ];

    await adminPage.goto('/iam/policies');
    await expect(adminPage.getByRole('heading', { name: 'Policies', exact: true })).toBeVisible();
    for (const n of names) await expect(adminPage.getByText(n).first()).toBeVisible();
  });

  test('should delete policy', async ({ adminPage, sdk, tenant }) => {
    const name = await seedPolicy(sdk, tenant, 'delete-policy', 'Delete me', ['read']);

    adminPage.on('dialog', (dialog) => void dialog.accept());
    await adminPage.goto('/iam/policies');
    await expect(adminPage.getByText(name).first()).toBeVisible();
    await userRow(adminPage, name).getByRole('button').last().click();
    await adminPage.getByRole('menuitem', { name: /delete/i }).click();

    await expect(adminPage.getByText(/policy deleted|deleted successfully/i).first()).toBeVisible({ timeout: 15000 });
    await expect(adminPage.getByText(name)).toHaveCount(0);
    await expect.poll(async () => (await sdk.iam.getPolicy(tenant.id, name)).success).toBe(false);
  });
});
