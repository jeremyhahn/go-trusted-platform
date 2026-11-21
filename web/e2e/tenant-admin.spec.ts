import { test, expect, type Page } from '@playwright/test';
import { createTenantAdminSession } from './fixtures/auth-setup';
import {
  mockAdminTenantsApi,
  createMockAdminTenant,
  type AdminTenantCall,
} from './fixtures/api-mock';

/**
 * Admin tenant lifecycle, quota and DEK pages (#1673): every operation of
 * the slice is driven from /admin/tenants or /admin/tenants/<id> against the
 * mocked tenant API, and each test asserts the request the page sent.
 */

const DETAIL = '/admin/tenants/tenant-1/';

function lastCall(calls: AdminTenantCall[], method: string, suffix: string): AdminTenantCall | undefined {
  return [...calls].reverse().find((c) => c.method === method && c.path.endsWith(suffix));
}

async function confirm(page: Page) {
  const dialog = page.getByTestId('confirm-dialog');
  await expect(dialog).toBeVisible();
  await dialog.getByTestId('confirm-action').click();
}

test.describe('Admin tenant lifecycle, quota and DEK (#1673)', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantAdminSession(page.context());
  });

  test.describe('tenant list', () => {
    test('ListTenants shows every tenant', async ({ page }) => {
      await mockAdminTenantsApi(page, {
        tenants: [
          createMockAdminTenant(),
          createMockAdminTenant({ id: 'tenant-2', name: 'globex', displayName: 'Globex', state: 'TENANT_STATE_SUSPENDED' }),
        ],
      });
      await page.goto('/admin/tenants/');
      const list = page.getByTestId('tenant-list');
      await expect(list.getByRole('link', { name: 'acme' })).toBeVisible();
      await expect(list.getByRole('link', { name: 'globex' })).toBeVisible();
      await expect(page.getByTestId('tenant-row-tenant-2')).toContainText('SUSPENDED');
    });

    test('ListTenants pages past the first 100 tenants', async ({ page }) => {
      const many = Array.from({ length: 120 }, (_, i) =>
        createMockAdminTenant({ id: `tenant-${i + 1}`, name: `t${String(i + 1).padStart(3, '0')}` }),
      );
      const api = await mockAdminTenantsApi(page, { tenants: many });
      await page.goto('/admin/tenants/');
      const list = page.getByTestId('tenant-list');
      await expect(list.getByRole('link', { name: 't001' })).toBeVisible();
      await expect(list.getByRole('link', { name: 't101' })).toHaveCount(0);
      await expect(page.getByTestId('tenant-page-info')).toContainText('of 120');

      await page.getByRole('button', { name: 'Next' }).click();
      await expect(list.getByRole('link', { name: 't120' })).toBeVisible();
      const query = lastCall(api.calls, 'GET', '/api/v1/tenants')?.query ?? '';
      expect(query).toContain('limit=100');
      expect(query).toContain('offset=100');
    });

    test('CreateTenant adds a tenant', async ({ page }) => {
      const api = await mockAdminTenantsApi(page);
      await page.goto('/admin/tenants/');
      await page.getByLabel('Name', { exact: true }).fill('initech');
      await page.getByLabel('Display name').fill('Initech');
      await page.getByRole('button', { name: 'Create' }).click();
      await expect(page.getByTestId('action-result')).toHaveText('Created tenant initech');
      await expect(page.getByTestId('tenant-list').getByRole('link', { name: 'initech' })).toBeVisible();
      expect(lastCall(api.calls, 'POST', '/api/v1/tenants')?.body).toMatchObject({
        name: 'initech',
        displayName: 'Initech',
      });
    });

    test('GetTenantByName finds a tenant by name', async ({ page }) => {
      const api = await mockAdminTenantsApi(page);
      await page.goto('/admin/tenants/');
      await page.getByLabel('Tenant name').fill('acme');
      await page.getByRole('button', { name: 'Find' }).click();
      await expect(page.getByTestId('search-result').getByRole('link', { name: 'acme' })).toBeVisible();
      expect(lastCall(api.calls, 'GET', '/by-name/acme')).toBeDefined();

      await page.getByLabel('Tenant name').fill('nobody');
      await page.getByRole('button', { name: 'Find' }).click();
      await expect(page.getByTestId('search-result')).toHaveCount(0);
      await expect(page.getByTestId('action-result')).not.toHaveText('');
    });

    test('DeleteTenant removes a tenant after confirm', async ({ page }) => {
      const api = await mockAdminTenantsApi(page);
      await page.goto('/admin/tenants/');
      await page.getByTestId('tenant-row-tenant-1').getByRole('button', { name: 'Delete' }).click();
      // Cancel first: nothing is deleted.
      await page.getByTestId('confirm-dialog').getByRole('button', { name: 'Cancel' }).click();
      expect(lastCall(api.calls, 'DELETE', '/tenant-1')).toBeUndefined();

      await page.getByTestId('tenant-row-tenant-1').getByRole('button', { name: 'Delete' }).click();
      await confirm(page);
      await expect(page.getByTestId('action-result')).toHaveText('Deleted tenant acme');
      await expect(page.getByTestId('tenant-row-tenant-1')).toHaveCount(0);
      expect(lastCall(api.calls, 'DELETE', '/tenant-1')).toBeDefined();
    });
  });

  test.describe('tenant detail', () => {
    test('UpdateTenant saves the display name', async ({ page }) => {
      const api = await mockAdminTenantsApi(page);
      await page.goto(DETAIL);
      const field = page.getByLabel('Display name');
      await expect(field).toHaveValue('Acme Corp');
      await field.fill('Acme Industries');
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByTestId('action-result')).toHaveText('Tenant updated');
      expect(lastCall(api.calls, 'PUT', '/tenant-1')?.body).toMatchObject({ displayName: 'Acme Industries' });
    });

    test('UpdateTenant refuses an empty display name', async ({ page }) => {
      const api = await mockAdminTenantsApi(page);
      await page.goto(DETAIL);
      const field = page.getByLabel('Display name');
      await expect(field).toHaveValue('Acme Corp');
      await field.fill('');
      await page.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(page.getByTestId('action-result')).toHaveText('Display name cannot be empty');
      expect(lastCall(api.calls, 'PUT', '/tenant-1')).toBeUndefined();
    });

    test('SuspendTenant suspends after confirm', async ({ page }) => {
      const api = await mockAdminTenantsApi(page);
      await page.goto(DETAIL);
      await page.getByRole('button', { name: 'Suspend' }).click();
      await confirm(page);
      await expect(page.getByTestId('action-result')).toHaveText('Tenant suspended');
      await expect(page.getByTestId('tenant-state')).toHaveText('SUSPENDED');
      await expect(page.getByRole('button', { name: 'Resume' })).toBeVisible();
      expect(lastCall(api.calls, 'POST', '/tenant-1/suspend')).toBeDefined();
    });

    test('ResumeTenant resumes a suspended tenant', async ({ page }) => {
      const api = await mockAdminTenantsApi(page, { tenants: [createMockAdminTenant({ state: 'TENANT_STATE_SUSPENDED' })] });
      await page.goto(DETAIL);
      await page.getByRole('button', { name: 'Resume' }).click();
      await expect(page.getByTestId('action-result')).toHaveText('Tenant resumed');
      await expect(page.getByTestId('tenant-state')).toHaveText('ACTIVE');
      expect(lastCall(api.calls, 'POST', '/tenant-1/resume')).toBeDefined();
    });

    test('UpdateQuotas saves quotas', async ({ page }) => {
      const api = await mockAdminTenantsApi(page);
      await page.goto(DETAIL);
      await expect(page.getByTestId('current-quota')).toContainText('VMs 10');
      // Only Max VMs is edited: the other limits, maxContainers included,
      // must be sent with their current values, because the server replaces
      // the whole compute section.
      await page.getByLabel('Max VMs').fill('20');
      await page.getByRole('button', { name: 'Save quotas' }).click();
      await expect(page.getByTestId('action-result')).toHaveText('Quotas updated');
      await expect(page.getByTestId('current-quota')).toContainText('VMs 20, vCPUs 40, memory 65536 MB');
      expect(lastCall(api.calls, 'PUT', '/tenant-1/quotas')?.body).toEqual({
        compute: { maxVms: 20, maxContainers: 5, maxVcpus: 40, maxMemoryMb: 65536 },
      });
    });

    test('CheckQuota reports a resource check', async ({ page }) => {
      const api = await mockAdminTenantsApi(page, { quotaAvailable: false });
      await page.goto(DETAIL);
      await page.getByLabel('Resource').fill('vcpus');
      await page.getByLabel('Amount').fill('8');
      await page.getByRole('button', { name: 'Check quota' }).click();
      await expect(page.getByTestId('action-result')).toHaveText('Quota exceeded for 8 vcpus');
      expect(lastCall(api.calls, 'POST', '/tenant-1/quota-check')?.body).toEqual({ resource: 'vcpus', amount: 8 });
    });

    test('Sync syncs the tenant', async ({ page }) => {
      const api = await mockAdminTenantsApi(page);
      await page.goto(DETAIL);
      await page.getByRole('button', { name: 'Sync tenants' }).click();
      await expect(page.getByTestId('action-result')).toHaveText('Tenants synced');
      expect(lastCall(api.calls, 'POST', '/api/v1/tenants/sync')).toBeDefined();
    });

    test('RotateTenantDEK rotates after confirm', async ({ page }) => {
      const api = await mockAdminTenantsApi(page);
      await page.goto(DETAIL);
      await page.getByRole('button', { name: 'Rotate DEK' }).click();
      await confirm(page);
      await expect(page.getByTestId('action-result')).toHaveText('DEK rotated from version 1 to 2');
      await expect(page.getByTestId('dek-status')).toContainText('Version 2');
      expect(lastCall(api.calls, 'POST', '/tenant-1/dek/rotate')).toBeDefined();
    });

    test('GetTenantDEKStatus shows the DEK status', async ({ page }) => {
      const api = await mockAdminTenantsApi(page);
      await page.goto(DETAIL);
      await expect(page.getByTestId('dek-status')).toContainText('Version 1, AES-256-GCM, ACTIVE, usage 1%');
      expect(lastCall(api.calls, 'GET', '/tenant-1/dek')).toBeDefined();
    });

    test('InitTenantBarrier initialises the barrier', async ({ page }) => {
      const api = await mockAdminTenantsApi(page);
      await page.goto(DETAIL);
      // Tenant barriers take no Shamir settings: the server refuses any
      // non-zero threshold or shares.
      await expect(page.getByLabel('Threshold')).toHaveCount(0);
      await expect(page.getByLabel('Shares')).toHaveCount(0);
      await page.getByRole('button', { name: 'Initialise barrier' }).click();
      await expect(page.getByTestId('action-result')).toHaveText('Barrier initialised');
      expect(lastCall(api.calls, 'POST', '/tenant-1/barrier/init')?.body).toEqual({});
    });

    test('UnsealTenantBarrier unseals the barrier', async ({ page }) => {
      const api = await mockAdminTenantsApi(page);
      await page.goto(DETAIL);
      await page.getByLabel('Unseal key (base64)').fill('dW5zZWFsLWtleQ==');
      await page.getByRole('button', { name: 'Unseal barrier' }).click();
      await expect(page.getByTestId('action-result')).toHaveText('Barrier unsealed');
      expect(lastCall(api.calls, 'POST', '/tenant-1/barrier/unseal')?.body).toEqual({ key: 'dW5zZWFsLWtleQ==' });
    });

    test('SealTenantBarrier seals after confirm', async ({ page }) => {
      const api = await mockAdminTenantsApi(page);
      await page.goto(DETAIL);
      await page.getByRole('button', { name: 'Seal barrier' }).click();
      await confirm(page);
      await expect(page.getByTestId('action-result')).toHaveText('Barrier sealed');
      expect(lastCall(api.calls, 'POST', '/tenant-1/barrier/seal')).toBeDefined();
    });
  });
});
