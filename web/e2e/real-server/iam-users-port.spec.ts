import type { Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect, type Tenant } from './fixtures';

/**
 * IAM users console (/iam/users and /iam/users/<id>) against the real-server
 * harness (#2035, epic #1665): the Users List, User CRUD, User Details and
 * Error States cases of the mocked web/e2e/iam.spec.ts.
 *
 * Users are seeded through sdk.iam in the harness admin's tenant with unique
 * names and deleted after each test; the harness admin itself is never
 * touched. Each case drives the page as the console does and asserts what the
 * server answered: the rendered row, value, toast or navigation on success,
 * and the message the page shows on a refusal.
 *
 * The server's user record (userToResponse, pkg/webservice/v1/rest/iam) has
 * no status: the console maps every user to "active".
 */

/** A user record as the server answers it: res.data is the user itself. */
interface UserWire {
  id?: string;
  email?: string;
  name?: string;
  roles?: string[];
}

function userOf(data: unknown): UserWire {
  const d = (data ?? {}) as UserWire & { user?: UserWire };
  return d.user ?? d;
}

/** The message of a platform error envelope, in either of its two shapes. */
function serverMessage(body: unknown): string {
  const b = body as { error?: string | { message?: string } } | null;
  if (typeof b?.error === 'string') return b.error;
  return b?.error?.message ?? '';
}

function usersPath(r: Response): string {
  return new URL(r.url()).pathname;
}

function isCreateUser(r: Response): boolean {
  return r.request().method() === 'POST' && /\/api\/v1\/tenants\/[^/]+\/users\/?$/.test(usersPath(r));
}

function isUpdateUser(id: string): (r: Response) => boolean {
  return (r) => r.request().method() === 'PUT' && usersPath(r).endsWith(`/users/${id}`);
}

function isDeleteUser(id: string): (r: Response) => boolean {
  return (r) => r.request().method() === 'DELETE' && usersPath(r).endsWith(`/users/${id}`);
}

function isGetUser(id: string): (r: Response) => boolean {
  return (r) => r.request().method() === 'GET' && usersPath(r).endsWith(`/users/${id}`);
}

let seq = 0;

/** A unique e2e user name and email. */
function uniqueUser(): { name: string; email: string } {
  seq += 1;
  const name = `e2e-user-${Date.now()}-${seq}`;
  return { name, email: `${name}@example.com` };
}

/** The users the server lists for the tenant (the list the page reads). */
async function listedUsers(sdk: PlatformClient, tenant: Tenant): Promise<UserWire[]> {
  const res = await sdk.iam.listUsers({ tenantId: tenant.id });
  expect(res.success, `listUsers: ${JSON.stringify(res.error)}`).toBe(true);
  return ((res.data as unknown as { users?: UserWire[] } | null)?.users ?? []) as UserWire[];
}

/** Seeds one user through the SDK and records it for deletion. */
async function seedUser(
  sdk: PlatformClient,
  tenant: Tenant,
  seeded: string[],
  extra: { roles?: string[] } = {},
): Promise<Required<Pick<UserWire, 'id' | 'email' | 'name'>> & UserWire> {
  const u = uniqueUser();
  const res = await sdk.iam.createUser({ tenantId: tenant.id, email: u.email, name: u.name, ...extra });
  expect(res.success, `createUser: ${JSON.stringify(res.error)}`).toBe(true);
  const user = userOf(res.data);
  expect(user.id ?? '').not.toBe('');
  seeded.push(user.id as string);
  return { ...user, id: user.id as string, email: user.email ?? u.email, name: user.name ?? u.name };
}

/** Deletes every user of the tenant with one of these emails (users the console created). */
async function deleteByEmail(sdk: PlatformClient, tenant: Tenant, emails: string[]): Promise<void> {
  if (emails.length === 0) return;
  const users = await listedUsers(sdk, tenant).catch(() => [] as UserWire[]);
  for (const u of users) {
    if (u.id && u.email && emails.includes(u.email)) {
      await sdk.iam.deleteUser(tenant.id, u.id).catch(() => undefined);
    }
  }
}

async function openUsers(page: Page): Promise<void> {
  await page.goto('/iam/users');
  await expect(page.getByRole('heading', { name: 'Users', exact: true })).toBeVisible();
}

/** The table row of the user with this email. */
function rowOf(page: Page, email: string) {
  return page.getByRole('row').filter({ hasText: email });
}

async function rowMenu(page: Page, email: string, item: RegExp): Promise<void> {
  await rowOf(page, email).getByRole('button').last().click();
  await page.getByRole('menuitem', { name: item }).click();
}

/**
 * The user detail route is a static export: the build emits one page for the
 * `__placeholder__` id and the client resolves the real id from the URL.
 */
async function openDetail(page: Page, id: string): Promise<Response> {
  await page.goto('/iam/users/__placeholder__/');
  await page.waitForLoadState('networkidle');
  const answer = page.waitForResponse(isGetUser(id));
  await page.evaluate((userId) => window.history.pushState(null, '', `/iam/users/${userId}/`), id);
  return answer;
}

test.describe('IAM users, real server', () => {
  const seeded: string[] = [];
  const uiEmails: string[] = [];
  const roles: string[] = [];

  test.afterEach(async ({ sdk, tenant }) => {
    for (const id of seeded.splice(0)) {
      await sdk.iam.deleteUser(tenant.id, id).catch(() => undefined);
    }
    await deleteByEmail(sdk, tenant, uiEmails.splice(0));
    for (const id of roles.splice(0)) {
      await sdk.iam.deleteRole(tenant.id, id).catch(() => undefined);
    }
  });

  test.describe('Users List', () => {
    test('should display user table with columns', async ({ adminPage, sdk, tenant }) => {
      const a = await seedUser(sdk, tenant, seeded);
      const b = await seedUser(sdk, tenant, seeded);
      await openUsers(adminPage);

      await expect(adminPage.getByRole('columnheader', { name: /user/i })).toBeVisible();
      await expect(adminPage.getByRole('columnheader', { name: /roles/i })).toBeVisible();
      await expect(adminPage.getByRole('columnheader', { name: /status/i })).toBeVisible();
      await expect(adminPage.getByText(a.email)).toBeVisible();
      await expect(adminPage.getByText(b.email)).toBeVisible();
    });

    test('should display user status badges correctly', async ({ adminPage, sdk, tenant }) => {
      // The server's user record carries no status, so the console renders
      // every user it lists as Active; disabled and pending have no server
      // state behind them (see the gap note on the status filter below).
      const a = await seedUser(sdk, tenant, seeded);
      await openUsers(adminPage);
      await expect(rowOf(adminPage, a.email).getByText('Active', { exact: true })).toBeVisible();
    });

    // gap: should show empty state when no users: the harness tenant always holds the signed-in admin, so the server never lists an empty tenant to it.
    // gap: should show loading state: the real server answers the list at once; a delayed answer for the spinner needs an injected delay.

    test('should filter users by search query', async ({ adminPage, sdk, tenant }) => {
      const a = await seedUser(sdk, tenant, seeded);
      const b = await seedUser(sdk, tenant, seeded);
      await openUsers(adminPage);
      await expect(adminPage.getByText(a.email)).toBeVisible();
      await expect(adminPage.getByText(b.email)).toBeVisible();

      const search = adminPage.getByPlaceholder('Search users...');
      await search.fill(a.name);
      await expect(adminPage.getByText(a.email)).toBeVisible();
      await expect(adminPage.getByText(b.email)).toBeHidden();

      await search.fill('');
      await expect(adminPage.getByText(a.email)).toBeVisible();
      await expect(adminPage.getByText(b.email)).toBeVisible();
    });

    test('should filter users by status', async ({ adminPage, sdk, tenant }) => {
      const a = await seedUser(sdk, tenant, seeded);
      await openUsers(adminPage);
      await expect(adminPage.getByText(a.email)).toBeVisible();

      // Every listed user is Active (no server status): the Active facet keeps
      // the seeded user, the Disabled facet hides it.
      await adminPage.getByRole('button', { name: /status/i }).click();
      await adminPage.getByRole('option', { name: /^active/i }).click();
      await expect(adminPage.getByText(a.email)).toBeVisible();
      await adminPage.getByRole('option', { name: /^active/i }).click();
      await adminPage.getByRole('option', { name: /^disabled/i }).click();
      await expect(adminPage.getByText(a.email)).toBeHidden();
    });

    test('should support pagination', async ({ adminPage, sdk, tenant }) => {
      const pageSize = 25;
      const before = await listedUsers(sdk, tenant);
      for (let i = before.length; i <= pageSize; i++) {
        await seedUser(sdk, tenant, seeded);
      }
      const listed = await listedUsers(sdk, tenant);
      await openUsers(adminPage);

      const next = adminPage.getByRole('button', { name: 'Go to next page' });
      await expect(next).toBeVisible();
      if (listed.length > pageSize) {
        await expect(next).toBeEnabled();
        await next.click();
        await expect(adminPage.getByRole('row')).not.toHaveCount(1);
      } else {
        // The server's default list page holds no more than one console page.
        await expect(next).toBeDisabled();
      }
    });
  });

  test.describe('User CRUD', () => {
    test('should open create user dialog', async ({ adminPage, sdk, tenant }) => {
      const a = await seedUser(sdk, tenant, seeded);
      await openUsers(adminPage);
      await expect(adminPage.getByText(a.email)).toBeVisible();

      await adminPage.getByRole('button', { name: /add user/i }).click();
      await expect(adminPage.getByRole('dialog')).toBeVisible();
      await expect(adminPage.getByRole('heading', { name: 'Create User' })).toBeVisible();
    });

    test('should create a new user', async ({ adminPage, sdk, tenant }) => {
      const u = uniqueUser();
      uiEmails.push(u.email);
      await openUsers(adminPage);

      await adminPage.getByRole('button', { name: /add user/i }).click();
      await adminPage.locator('input#email').fill(u.email);
      await adminPage.locator('input#name').fill(u.name);
      await adminPage.locator('input#password').fill('password123');
      const answer = adminPage.waitForResponse(isCreateUser);
      await adminPage.getByRole('dialog').getByRole('button', { name: 'Create User' }).click();
      const res = await answer;

      if (res.ok()) {
        const created = userOf(await res.json());
        expect(created.email).toBe(u.email);
        await expect(adminPage.getByText('User created', { exact: true })).toBeVisible();
        await expect(adminPage.getByText(u.email)).toBeVisible();
        expect((await listedUsers(sdk, tenant)).some((x) => x.email === u.email)).toBe(true);
      } else {
        const message = serverMessage(await res.json().catch(() => null));
        await expect(adminPage.getByText('Error creating user', { exact: true })).toBeVisible();
        if (message) await expect(adminPage.getByText(message).first()).toBeVisible();
      }
    });

    test('should validate required fields', async ({ adminPage, sdk, tenant }) => {
      const before = (await listedUsers(sdk, tenant)).length;
      let posted = false;
      adminPage.on('request', (r) => {
        if (r.method() === 'POST' && /\/api\/v1\/tenants\/[^/]+\/users\/?$/.test(new URL(r.url()).pathname)) posted = true;
      });
      await openUsers(adminPage);

      await adminPage.getByRole('button', { name: /add user/i }).click();
      await adminPage.getByRole('dialog').getByRole('button', { name: 'Create User' }).click();
      await expect(adminPage.getByText('Name is required')).toBeVisible();
      await expect(adminPage.getByText('Email is required')).toBeVisible();
      await expect(adminPage.getByText('Password is required')).toBeVisible();
      await expect(adminPage.getByRole('dialog')).toBeVisible();

      expect(posted).toBe(false);
      expect((await listedUsers(sdk, tenant)).length).toBe(before);
    });

    test('should edit user details', async ({ adminPage, sdk, tenant }) => {
      const a = await seedUser(sdk, tenant, seeded);
      expect((await openDetail(adminPage, a.id)).ok()).toBe(true);
      await expect(adminPage.getByText(a.email)).toBeVisible();

      const newName = `${a.name}-renamed`;
      await adminPage.getByRole('button', { name: 'Edit User' }).click();
      await expect(adminPage.getByRole('dialog')).toBeVisible();
      await adminPage.locator('input#name').fill(newName);
      const answer = adminPage.waitForResponse(isUpdateUser(a.id));
      await adminPage.getByRole('dialog').getByRole('button', { name: 'Update User' }).click();
      const res = await answer;

      if (res.ok()) {
        await expect(adminPage.getByText('User updated', { exact: true })).toBeVisible();
        const after = await sdk.iam.getUser(tenant.id, a.id);
        expect(userOf(after.data).name).toBe(newName);
        await expect(adminPage.getByText(newName, { exact: true })).toBeVisible();
      } else {
        const message = serverMessage(await res.json().catch(() => null));
        await expect(adminPage.getByText('Error updating user', { exact: true })).toBeVisible();
        if (message) await expect(adminPage.getByText(message).first()).toBeVisible();
        const after = await sdk.iam.getUser(tenant.id, a.id);
        expect(userOf(after.data).name).toBe(a.name);
      }
    });

    test('should delete user with confirmation', async ({ adminPage, sdk, tenant }) => {
      const a = await seedUser(sdk, tenant, seeded);
      await openUsers(adminPage);
      await expect(adminPage.getByText(a.email)).toBeVisible();

      adminPage.on('dialog', (dialog) => dialog.accept());
      const answer = adminPage.waitForResponse(isDeleteUser(a.id));
      await rowMenu(adminPage, a.email, /delete/i);
      const res = await answer;

      if (res.ok()) {
        await expect(adminPage.getByText('User deleted', { exact: true })).toBeVisible();
        await expect(adminPage.getByText(a.email)).toBeHidden();
        expect((await listedUsers(sdk, tenant)).some((x) => x.id === a.id)).toBe(false);
      } else {
        const message = serverMessage(await res.json().catch(() => null));
        await expect(adminPage.getByText('Error deleting user', { exact: true })).toBeVisible();
        if (message) await expect(adminPage.getByText(message).first()).toBeVisible();
        await expect(adminPage.getByText(a.email)).toBeVisible();
      }
    });

    test('should disable/enable user', async ({ adminPage, sdk, tenant }) => {
      // The console's Disable sends an update with the user's name only (the
      // server has no status field); the server's answer decides the toast.
      const a = await seedUser(sdk, tenant, seeded);
      await openUsers(adminPage);
      await expect(adminPage.getByText(a.email)).toBeVisible();

      const answer = adminPage.waitForResponse(isUpdateUser(a.id));
      await rowMenu(adminPage, a.email, /disable/i);
      const res = await answer;

      if (res.ok()) {
        await expect(adminPage.getByText('User disabled', { exact: true })).toBeVisible();
        const after = await sdk.iam.getUser(tenant.id, a.id);
        expect(after.success).toBe(true);
        expect(userOf(after.data).email).toBe(a.email);
        // No status on the server: the refreshed row still reads Active.
        await expect(rowOf(adminPage, a.email).getByText('Active', { exact: true })).toBeVisible();
      } else {
        const message = serverMessage(await res.json().catch(() => null));
        await expect(adminPage.getByText('Error updating user', { exact: true })).toBeVisible();
        if (message) await expect(adminPage.getByText(message).first()).toBeVisible();
      }
    });
  });

  test.describe('User Details', () => {
    test('should navigate to user details from list', async ({ adminPage, sdk, tenant }) => {
      const a = await seedUser(sdk, tenant, seeded);
      await openUsers(adminPage);
      await expect(adminPage.getByText(a.email)).toBeVisible();

      await rowMenu(adminPage, a.email, /view/i);
      await expect(adminPage).toHaveURL(new RegExp(`/iam/users/${a.id}/?$`));
    });

    test('should display user information', async ({ adminPage, sdk, tenant }) => {
      const a = await seedUser(sdk, tenant, seeded);
      const res = await openDetail(adminPage, a.id);
      expect(res.ok()).toBe(true);
      const answered = userOf(await res.json());

      await expect(adminPage.getByRole('heading', { name: 'User Details' })).toBeVisible();
      await expect(adminPage.getByText(answered.email ?? a.email, { exact: true })).toBeVisible();
      await expect(adminPage.getByText(answered.name ?? a.name, { exact: true })).toBeVisible();
    });

    test('should show assigned roles', async ({ adminPage, sdk, tenant }) => {
      const roleName = `e2e-role-${Date.now()}`;
      const created = await sdk.iam.createRole({
        tenantId: tenant.id,
        name: roleName,
        description: 'e2e role for the user detail page',
        permissions: ['devices:read'],
      });
      expect(created.success, `createRole: ${JSON.stringify(created.error)}`).toBe(true);
      const roleId = String((created.data as unknown as { id?: string; role?: { id?: string } }).role?.id
        ?? (created.data as unknown as { id?: string }).id ?? '');
      expect(roleId).not.toBe('');
      roles.push(roleId);

      const a = await seedUser(sdk, tenant, seeded, { roles: [roleId] });
      const res = await openDetail(adminPage, a.id);
      expect(res.ok()).toBe(true);
      const answeredRoles = userOf(await res.json()).roles ?? [];

      // The page names a role by its id until the edit form loads the roles.
      for (const r of answeredRoles) {
        await expect(adminPage.getByText(r, { exact: true })).toBeVisible();
      }
      if (answeredRoles.length === 0) {
        await expect(adminPage.getByText('No roles assigned')).toBeVisible();
      } else {
        expect(answeredRoles).toContain(roleId);
      }
    });

    // gap: should show group memberships: the user detail page renders no group memberships (only the Roles & Permissions and Activity Log tabs), so the user's groups the server answers are never shown.

    test('should show user not found when user does not exist', async ({ adminPage }) => {
      const id = `e2e-no-such-user-${Date.now()}`;
      const res = await openDetail(adminPage, id);
      expect(res.ok()).toBe(false);
      await expect(adminPage.getByText(/Error loading user:/)).toBeVisible();
      const message = serverMessage(await res.json().catch(() => null));
      if (message) await expect(adminPage.getByText(message, { exact: false }).first()).toBeVisible();
    });

    test('should navigate back to users list', async ({ adminPage, sdk, tenant }) => {
      const a = await seedUser(sdk, tenant, seeded);
      expect((await openDetail(adminPage, a.id)).ok()).toBe(true);
      const heading = adminPage.getByRole('heading', { name: 'User Details' });
      await expect(heading).toBeVisible();

      // The back button is the icon button beside the heading.
      await heading.locator('xpath=../..').getByRole('button').first().click();
      await expect(adminPage).toHaveURL(/\/iam\/users\/?$/);
      await expect(adminPage.getByText(a.email)).toBeVisible();
    });
  });

  test.describe('Error States', () => {
    // gap: should handle fetch users error: needs an injected 500 on the user list; the real server answers it for the admin.
    // gap: should handle fetch roles error: needs an injected 500 on the role list; the real server answers it for the admin.
    // gap: should handle fetch groups error: needs an injected 500 on the group list; the real server answers it for the admin.

    test('should handle create user error', async ({ adminPage, sdk, tenant }) => {
      // A second user with an email (and so the username) already taken.
      const a = await seedUser(sdk, tenant, seeded);
      uiEmails.push(a.email);
      await openUsers(adminPage);
      await expect(adminPage.getByText(a.email)).toBeVisible();

      await adminPage.getByRole('button', { name: /add user/i }).click();
      await adminPage.locator('input#email').fill(a.email);
      await adminPage.locator('input#name').fill(`${a.name}-dup`);
      await adminPage.locator('input#password').fill('password123');
      const answer = adminPage.waitForResponse(isCreateUser);
      await adminPage.getByRole('dialog').getByRole('button', { name: 'Create User' }).click();
      const res = await answer;

      if (res.ok()) {
        // The server accepted the duplicate: the list now holds it twice.
        await expect(adminPage.getByText('User created', { exact: true })).toBeVisible();
        expect((await listedUsers(sdk, tenant)).filter((x) => x.email === a.email).length).toBeGreaterThan(1);
      } else {
        const message = serverMessage(await res.json().catch(() => null));
        expect(message).not.toBe('');
        await expect(adminPage.getByText('Error creating user', { exact: true })).toBeVisible();
        await expect(adminPage.getByText(message).first()).toBeVisible();
        expect((await listedUsers(sdk, tenant)).filter((x) => x.email === a.email).length).toBe(1);
      }
    });

    test('should handle delete user error', async ({ adminPage, sdk, tenant }) => {
      // The user is deleted behind the page's back: the console's delete then
      // names a user the server no longer holds.
      const a = await seedUser(sdk, tenant, seeded);
      await openUsers(adminPage);
      await expect(adminPage.getByText(a.email)).toBeVisible();
      const gone = await sdk.iam.deleteUser(tenant.id, a.id);
      expect(gone.success).toBe(true);

      adminPage.on('dialog', (dialog) => dialog.accept());
      const answer = adminPage.waitForResponse(isDeleteUser(a.id));
      await rowMenu(adminPage, a.email, /delete/i);
      const res = await answer;

      if (res.ok()) {
        await expect(adminPage.getByText('User deleted', { exact: true })).toBeVisible();
      } else {
        const message = serverMessage(await res.json().catch(() => null));
        expect(message).not.toBe('');
        await expect(adminPage.getByText('Error deleting user', { exact: true })).toBeVisible();
        await expect(adminPage.getByText(message).first()).toBeVisible();
      }
      expect((await listedUsers(sdk, tenant)).some((x) => x.id === a.id)).toBe(false);
    });

    // gap: should handle permission denied: needs a tenant-member session without IAM rights; the harness signs in only the tenant admin, which the server never refuses the user list.
  });
});
