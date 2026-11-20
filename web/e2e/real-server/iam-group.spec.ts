/**
 * Real-server spec for the IAM group, permission, token and tenant
 * operations (issue #2053, epic #1665, coverage-matrix slice 16).
 *
 * State is seeded through the SDK client (`sdk`) against the harness
 * server; nothing is mocked. Each test asserts on what the server returns.
 */
import { test, expect } from './fixtures';

const unique = (prefix: string) =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;

test.describe('IAM groups', () => {
  test('CreateGroup: the new-group form creates a group the server lists', async ({ adminPage, sdk, tenant }) => {
    const name = unique('e2e-group');
    await adminPage.goto('/iam/groups/new');
    await adminPage.getByLabel('Name').fill(name);
    await adminPage.getByLabel('Description').fill('created by iam-group.spec');
    await adminPage.getByRole('button', { name: /create group/i }).click();

    await expect(adminPage).toHaveURL(/\/iam\/groups/);
    const listed = await sdk.iam.listGroups({ tenantId: tenant.id });
    const groups = (listed.data as unknown as { groups?: { name?: string }[] }).groups ?? [];
    expect(groups.map((g) => g.name)).toContain(name);
  });

  test('GetGroup: the detail page shows the group the server returns', async ({ adminPage, sdk, tenant }) => {
    const name = unique('e2e-get');
    const created = await sdk.iam.createGroup({ tenantId: tenant.id, name, description: 'get me' });
    const id = groupId(created.data);

    await adminPage.goto(`/iam/groups/${id}`);
    await expect(adminPage.getByText(name).first()).toBeVisible();
    await expect(adminPage.getByText('get me').first()).toBeVisible();
  });

  test('UpdateGroup: saving the edit form changes the group on the server', async ({ adminPage, sdk, tenant }) => {
    const created = await sdk.iam.createGroup({ tenantId: tenant.id, name: unique('e2e-upd'), description: 'before' });
    const id = groupId(created.data);
    const renamed = unique('e2e-renamed');

    await adminPage.goto(`/iam/groups/${id}`);
    await adminPage.getByLabel('Name', { exact: true }).fill(renamed);
    await adminPage.getByLabel('Description', { exact: true }).fill('after');
    await adminPage.getByRole('button', { name: 'Save group' }).click();
    await expect(adminPage.getByText('Group updated').first()).toBeVisible();

    const g = unwrapGroup((await sdk.iam.getGroup(tenant.id, id)).data);
    expect(g.name).toBe(renamed);
    expect(g.description).toBe('after');
  });

  test('AddGroupMember and RemoveGroupMember: controls are gated off with the backend reason', async ({ adminPage, sdk, tenant }) => {
    const created = await sdk.iam.createGroup({ tenantId: tenant.id, name: unique('e2e-mem') });
    const id = groupId(created.data);

    await adminPage.goto(`/iam/groups/${id}`);
    await expect(adminPage.getByRole('button', { name: /add member/i })).toBeDisabled();
    await expect(adminPage.getByRole('button', { name: /remove by user id/i })).toBeDisabled();
    await expect(adminPage.getByText(/does not implement Group\.AddMember/)).toBeVisible();
    await expect(adminPage.getByText(/does not implement Group\.RemoveMember/)).toBeVisible();
  });
});

test.describe('IAM permission check', () => {
  test('CheckPermission: the check form shows the server decision', async ({ adminPage, sdk, tenant }) => {
    const request = {
      tenantId: tenant.id,
      subjectId: 'e2e-subject',
      action: 'read',
      resource: '/api/v1/secrets/e2e',
    };
    const expected = await sdk.iam.checkPermission(request);

    await adminPage.goto('/iam/permissions');
    await adminPage.getByLabel('Subject ID').fill(request.subjectId);
    await adminPage.getByLabel('Action', { exact: true }).fill(request.action);
    await adminPage.getByLabel('Resource', { exact: true }).fill(request.resource);
    await adminPage.getByRole('button', { name: 'Check permission' }).click();

    const result = adminPage.getByTestId('permission-check-result');
    if (expected.success) {
      const allowed = Boolean((expected.data as unknown as { allowed?: boolean }).allowed);
      await expect(result).toHaveText(allowed ? /allowed/i : /denied/i);
    } else {
      // The server refused the check (no PEP configured): the page shows its error.
      await expect(result).toHaveText(/error/i);
    }
  });
});

test.describe('IAM tokens', () => {
  test('CreateToken, VerifyToken and RevokeToken: controls are gated off until the REST routes exist', async ({ adminPage }) => {
    await adminPage.goto('/iam/tokens');
    for (const name of ['Create token', 'Verify token', 'Revoke token']) {
      const control = adminPage.getByRole('button', { name, exact: true });
      await expect(control).toBeDisabled();
      await expect(control).toHaveAttribute('title', /not available/i);
    }
  });
});

test.describe('IAM tenants', () => {
  test('ListTenants: the tenants page lists the seeded tenant', async ({ adminPage, tenant }) => {
    await adminPage.goto('/iam/tenants');
    await expect(adminPage.getByText(tenant.id).first()).toBeVisible();
  });

  test('CreateTenant, GetTenant, UpdateTenant, DeleteTenant round-trip through the page', async ({ adminPage, sdk }) => {
    const id = unique('e2e-tenant');
    const name = `${id} name`;
    await adminPage.goto('/iam/tenants');
    await adminPage.getByLabel('Tenant ID').fill(id);
    await adminPage.getByLabel('Tenant name').fill(name);
    await adminPage.getByRole('button', { name: 'Create tenant' }).click();
    await expect(adminPage.getByText('Tenant created').first()).toBeVisible();
    expect(unwrapTenant((await sdk.iam.getTenant(id)).data).name).toBe(name);

    await adminPage.getByRole('button', { name: `View tenant ${id}` }).click();
    await expect(adminPage.getByTestId('tenant-detail')).toContainText(name);

    const renamed = `${id} renamed`;
    await adminPage.getByLabel('New name').fill(renamed);
    await adminPage.getByRole('button', { name: 'Save tenant' }).click();
    await expect(adminPage.getByText('Tenant updated').first()).toBeVisible();
    expect(unwrapTenant((await sdk.iam.getTenant(id)).data).name).toBe(renamed);

    await adminPage.getByRole('button', { name: `Delete tenant ${id}` }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Delete tenant' }).click();
    await expect(adminPage.getByText('Tenant deleted').first()).toBeVisible();
    const after = await sdk.iam.getTenant(id).catch(() => null);
    expect(after === null || after.success === false).toBe(true);
  });
});

interface WireRecord {
  id?: string;
  name?: string;
  description?: string;
}

function unwrapGroup(data: unknown): WireRecord {
  const d = data as { group?: WireRecord } & WireRecord;
  return d.group ?? d;
}

function unwrapTenant(data: unknown): WireRecord {
  const d = data as { tenant?: WireRecord } & WireRecord;
  return d.tenant ?? d;
}

function groupId(data: unknown): string {
  const id = unwrapGroup(data).id;
  if (!id) throw new Error('server returned a group without an id');
  return id;
}
