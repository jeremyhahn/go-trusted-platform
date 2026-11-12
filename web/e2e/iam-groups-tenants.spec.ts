import { test, expect } from '@playwright/test';
import { mockIAMGroupsTenantsApi, mockTenantApi } from './fixtures/api-mock';
import type { MockIAMGroup, MockIAMTenant } from './fixtures/api-mock';
import { createTenantOwnerSession } from './fixtures/auth-setup';

// Slice 16 of #1665 (#1744): IAM groups, group members, permission check and tenants.
// Every operation is driven from its page and asserted on the REST call it makes.

const engineering = (): MockIAMGroup => ({
  id: 'group-1',
  name: 'Engineering',
  description: 'Builds things',
  members: ['user-alice'],
});

const tenant = (id: string, name: string): MockIAMTenant => ({
  id,
  name,
  createdAt: '2026-11-01T00:00:00Z',
  updatedAt: '2026-11-01T00:00:00Z',
});

test.describe('IAM groups, members, permission check and tenants', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
    await mockTenantApi(page);
  });

  test('CreateGroup: POST /groups from the new group page', async ({ page }) => {
    const api = await mockIAMGroupsTenantsApi(page);
    await page.goto('/iam/groups/new');
    await page.getByLabel(/name/i).first().fill('Operations');
    await page.getByRole('button', { name: /create/i }).last().click();
    await expect
      .poll(() => api.calls.find((c) => c.method === 'POST' && /\/groups$/.test(c.path)))
      .toBeTruthy();
    expect(api.groups().map((g) => g.name)).toContain('Operations');
  });

  test('GetGroup: GET /groups/{id} on the group detail page', async ({ page }) => {
    const api = await mockIAMGroupsTenantsApi(page, { groups: [engineering()] });
    await page.goto('/iam/groups/group-1');
    await expect(page.getByText('Engineering').first()).toBeVisible();
    await expect(page.getByText('Builds things')).toBeVisible();
    expect(api.calls.some((c) => c.method === 'GET' && /\/groups\/group-1$/.test(c.path))).toBe(true);
  });

  test('UpdateGroup: PUT /groups/{id} from the group detail page', async ({ page }) => {
    const api = await mockIAMGroupsTenantsApi(page, { groups: [engineering()] });
    await page.goto('/iam/groups/group-1');
    await page.getByLabel('Name', { exact: true }).fill('Platform Engineering');
    await page.getByLabel('Description').fill('Runs the platform');
    await page.getByRole('button', { name: 'Save group' }).click();
    await expect
      .poll(() => api.calls.find((c) => c.method === 'PUT' && /\/groups\/group-1$/.test(c.path)))
      .toBeTruthy();
    const put = api.calls.find((c) => c.method === 'PUT');
    expect(put?.body).toMatchObject({ name: 'Platform Engineering', description: 'Runs the platform' });
    await expect(page.getByText('Platform Engineering').first()).toBeVisible();
  });

  test('AddGroupMember: POST /groups/{id}/members/{user}', async ({ page }) => {
    const api = await mockIAMGroupsTenantsApi(page, { groups: [engineering()] });
    await page.goto('/iam/groups/group-1');
    await page.getByLabel('User ID', { exact: true }).fill('user-bob');
    await page.getByRole('button', { name: 'Add member' }).click();
    await expect
      .poll(() =>
        api.calls.find((c) => c.method === 'POST' && /\/groups\/group-1\/members\/user-bob$/.test(c.path))
      )
      .toBeTruthy();
    await expect(page.getByText('Member added').first()).toBeVisible();
    expect(api.groups()[0]?.members).toContain('user-bob');
  });

  test('RemoveGroupMember: DELETE /groups/{id}/members/{user} by user ID behind a confirm', async ({ page }) => {
    // The real GET /groups/{id} carries no members list, so removal goes by user ID.
    const api = await mockIAMGroupsTenantsApi(page, { groups: [engineering()] });
    await page.goto('/iam/groups/group-1');
    await page.getByLabel('User ID to remove').fill('user-alice');
    await page.getByRole('button', { name: 'Remove by user ID' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Remove member?')).toBeVisible();
    expect(api.calls.some((c) => c.method === 'DELETE')).toBe(false);
    await dialog.getByRole('button', { name: 'Remove member' }).click();
    await expect
      .poll(() =>
        api.calls.find((c) => c.method === 'DELETE' && /\/groups\/group-1\/members\/user-alice$/.test(c.path))
      )
      .toBeTruthy();
    await expect(page.getByText('Member removed').first()).toBeVisible();
    expect(api.groups()[0]?.members).not.toContain('user-alice');
  });

  test('CheckPermission: POST /permissions/check', async ({ page }) => {
    const api = await mockIAMGroupsTenantsApi(page, { permissionAllowed: true });
    await page.goto('/iam/permissions');
    await page.getByLabel('Subject ID').fill('user-alice');
    await page.getByLabel('Action').fill('read');
    await page.getByLabel('Resource').fill('devices');
    await page.getByRole('button', { name: 'Check', exact: true }).click();
    await expect(page.getByRole('status').getByText('Allowed')).toBeVisible();
    const call = api.calls.find((c) => /\/permissions\/check$/.test(c.path));
    expect(call?.method).toBe('POST');
    expect(call?.body).toMatchObject({ subject_id: 'user-alice', action: 'read', resource: 'devices' });
    expect(call?.body).not.toHaveProperty('subjectId');
  });

  test('ListTenants: GET /tenants', async ({ page }) => {
    const api = await mockIAMGroupsTenantsApi(page, {
      tenants: [tenant('acme', 'Acme Corp'), tenant('globex', 'Globex')],
    });
    await page.goto('/iam/tenants');
    await expect(page.getByRole('heading', { name: 'Tenants', exact: true })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'Acme Corp' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'Globex' })).toBeVisible();
    expect(api.calls.some((c) => c.method === 'GET' && /\/tenants$/.test(c.path))).toBe(true);
  });

  test('CreateTenant: POST /tenants', async ({ page }) => {
    const api = await mockIAMGroupsTenantsApi(page);
    await page.goto('/iam/tenants');
    await expect(page.getByText('No tenants.')).toBeVisible();
    await page.getByLabel('Tenant ID').fill('initech');
    await page.getByLabel('Tenant name').fill('Initech');
    await page.getByRole('button', { name: 'Create tenant' }).click();
    await expect(page.getByRole('cell', { name: 'Initech' })).toBeVisible();
    const post = api.calls.find((c) => c.method === 'POST' && /\/tenants$/.test(c.path));
    expect(post?.body).toMatchObject({ id: 'initech', name: 'Initech' });
  });

  test('Create tenant stays disabled without an ID', async ({ page }) => {
    const api = await mockIAMGroupsTenantsApi(page);
    await page.goto('/iam/tenants');
    await expect(page.getByText('No tenants.')).toBeVisible();
    await page.getByLabel('Tenant name').fill('Initech');
    await expect(page.getByRole('button', { name: 'Create tenant' })).toBeDisabled();
    expect(api.calls.some((c) => c.method === 'POST' && /\/tenants$/.test(c.path))).toBe(false);
  });

  test('a failed tenant create keeps the form and shows the error', async ({ page }) => {
    const api = await mockIAMGroupsTenantsApi(page, { tenantFailOps: ['create'] });
    await page.goto('/iam/tenants');
    await expect(page.getByText('No tenants.')).toBeVisible();
    await page.getByLabel('Tenant ID').fill('initech');
    await page.getByLabel('Tenant name').fill('Initech');
    await page.getByRole('button', { name: 'Create tenant' }).click();
    await expect(page.getByText('Failed to create tenant').first()).toBeVisible();
    await expect(page.getByLabel('Tenant name')).toHaveValue('Initech');
    await expect(page.getByText('Tenant created')).toHaveCount(0);
    expect(api.tenants()).toHaveLength(0);
  });

  test('a failed tenant delete keeps the confirmation open', async ({ page }) => {
    const api = await mockIAMGroupsTenantsApi(page, {
      tenants: [tenant('globex', 'Globex')],
      tenantFailOps: ['delete'],
    });
    await page.goto('/iam/tenants');
    await page.getByRole('button', { name: 'Delete tenant globex' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Delete tenant' }).click();
    await expect(page.getByText('Failed to delete tenant').first()).toBeVisible();
    await expect(dialog.getByText('Delete tenant?')).toBeVisible();
    await expect(page.getByText('Tenant deleted')).toHaveCount(0);
    expect(api.tenants().map((t) => t.id)).toContain('globex');
  });

  test('GetTenant: GET /tenants/{tenant}', async ({ page }) => {
    const api = await mockIAMGroupsTenantsApi(page, { tenants: [tenant('acme', 'Acme Corp')] });
    await page.goto('/iam/tenants');
    await page.getByRole('button', { name: 'View tenant acme' }).click();
    const detail = page.getByTestId('tenant-detail');
    await expect(detail.getByText('Acme Corp')).toBeVisible();
    expect(api.calls.some((c) => c.method === 'GET' && /\/tenants\/acme$/.test(c.path))).toBe(true);
  });

  test('UpdateTenant: PUT /tenants/{tenant}', async ({ page }) => {
    const api = await mockIAMGroupsTenantsApi(page, { tenants: [tenant('acme', 'Acme Corp')] });
    await page.goto('/iam/tenants');
    await page.getByRole('button', { name: 'View tenant acme' }).click();
    await page.getByLabel('New name').fill('Acme Industries');
    await page.getByRole('button', { name: 'Save tenant' }).click();
    await expect(page.getByRole('cell', { name: 'Acme Industries' })).toBeVisible();
    const put = api.calls.find((c) => c.method === 'PUT' && /\/tenants\/acme$/.test(c.path));
    expect(put?.body).toMatchObject({ name: 'Acme Industries' });
  });

  test('DeleteTenant: DELETE /tenants/{tenant} behind a confirm', async ({ page }) => {
    const api = await mockIAMGroupsTenantsApi(page, {
      tenants: [tenant('acme', 'Acme Corp'), tenant('globex', 'Globex')],
    });
    await page.goto('/iam/tenants');
    await page.getByRole('button', { name: 'Delete tenant globex' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Delete tenant?')).toBeVisible();

    // Cancel sends nothing.
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    expect(api.calls.some((c) => c.method === 'DELETE')).toBe(false);

    await page.getByRole('button', { name: 'Delete tenant globex' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete tenant' }).click();
    await expect(page.getByRole('cell', { name: 'Globex' })).toHaveCount(0);
    expect(api.calls.some((c) => c.method === 'DELETE' && /\/tenants\/globex$/.test(c.path))).toBe(true);
    await expect(page.getByRole('cell', { name: 'Acme Corp' })).toBeVisible();
  });
});
