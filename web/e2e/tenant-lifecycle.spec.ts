import { test, expect, type Page } from '@playwright/test';
import { createTenantAdminSession } from './fixtures/auth-setup';
import { mockTenantApi, mockTenantLifecycleApi } from './fixtures/api-mock';

// Tenant lifecycle, quotas, sync and tenant DEK rotation (#1758, slice 30 of #1665).
// Every operation is driven from /tenant/lifecycle against mocked
// /api/v1/tenants responses.

type Mock = Awaited<ReturnType<typeof mockTenantLifecycleApi>>;

async function openLifecycle(page: Page, config: Parameters<typeof mockTenantLifecycleApi>[1] = {}) {
  await mockTenantApi(page);
  const mock = await mockTenantLifecycleApi(page, config);
  await page.goto('/tenant/lifecycle');
  await expect(page.locator('h1').filter({ hasText: /Tenant Lifecycle/i })).toBeVisible();
  return mock;
}

async function lookUp(page: Page, name = 'acme') {
  await page.getByLabel('Tenant name').fill(name);
  await page.getByRole('button', { name: 'Look up' }).click();
  await expect(page.getByTestId('tenant-details')).toBeVisible();
}

function called(mock: Mock, method: string, path: string) {
  return mock.calls.filter((c) => c.method === method && c.path === path);
}

async function confirmDialog(page: Page, title: string, button: string) {
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText(title)).toBeVisible();
  await dialog.getByRole('button', { name: button }).click();
  await expect(dialog).toBeHidden();
}

test.describe('Tenant lifecycle', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantAdminSession(page.context());
  });

  test('GetTenantByName looks a tenant up by name', async ({ page }) => {
    const mock = await openLifecycle(page);
    await lookUp(page);
    await expect(page.getByTestId('tenant-details')).toContainText('Acme Corp');
    await expect(page.getByTestId('tenant-state')).toHaveText('ACTIVE');
    expect(called(mock, 'GET', '/by-name/acme')).toHaveLength(1);
  });

  test('GetTenantByName shows an error for an unknown name', async ({ page }) => {
    await openLifecycle(page);
    await page.getByLabel('Tenant name').fill('nobody');
    await page.getByRole('button', { name: 'Look up' }).click();
    await expect(page.getByRole('alert')).toBeVisible();
    await expect(page.getByTestId('tenant-details')).toHaveCount(0);
  });

  test('UpdateTenant saves the display name', async ({ page }) => {
    const mock = await openLifecycle(page);
    await lookUp(page);
    await page.getByLabel('Display name').fill('Acme Renamed');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByRole('status')).toHaveText('Tenant updated');
    await expect(page.getByTestId('tenant-details')).toContainText('Acme Renamed');
    const puts = called(mock, 'PUT', '/tenant-abc-123');
    expect(puts).toHaveLength(1);
    expect(puts[0]?.body).toMatchObject({ tenantId: 'tenant-abc-123', displayName: 'Acme Renamed' });
  });

  test('DeleteTenant asks for confirmation first', async ({ page }) => {
    const mock = await openLifecycle(page);
    await lookUp(page);
    await page.getByRole('button', { name: 'Delete' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
    expect(called(mock, 'DELETE', '/tenant-abc-123')).toHaveLength(0);

    await page.getByRole('button', { name: 'Delete' }).click();
    await confirmDialog(page, 'Delete tenant', 'Delete');
    await expect(page.getByRole('status')).toHaveText('Tenant acme deleted');
    await expect(page.getByTestId('tenant-details')).toHaveCount(0);
    expect(called(mock, 'DELETE', '/tenant-abc-123')).toHaveLength(1);
  });

  test('SuspendTenant asks for confirmation first', async ({ page }) => {
    const mock = await openLifecycle(page);
    await lookUp(page);
    await page.getByRole('button', { name: 'Suspend' }).click();
    expect(called(mock, 'POST', '/tenant-abc-123/suspend')).toHaveLength(0);
    await confirmDialog(page, 'Suspend tenant', 'Suspend');
    await expect(page.getByTestId('tenant-state')).toHaveText('SUSPENDED');
    expect(called(mock, 'POST', '/tenant-abc-123/suspend')).toHaveLength(1);
  });

  test('ResumeTenant resumes a suspended tenant', async ({ page }) => {
    const mock = await openLifecycle(page, { tenant: { state: 'SUSPENDED' } });
    await lookUp(page);
    await expect(page.getByTestId('tenant-state')).toHaveText('SUSPENDED');
    await page.getByRole('button', { name: 'Resume' }).click();
    await expect(page.getByTestId('tenant-state')).toHaveText('ACTIVE');
    expect(called(mock, 'POST', '/tenant-abc-123/resume')).toHaveLength(1);
  });

  test('UpdateQuotas saves new quota limits', async ({ page }) => {
    const mock = await openLifecycle(page);
    await lookUp(page);
    await page.getByLabel('Maximum VMs').fill('12');
    await page.getByRole('button', { name: 'Save quotas' }).click();
    await expect(page.getByRole('status')).toHaveText('Quotas updated');
    const puts = called(mock, 'PUT', '/tenant-abc-123/quotas');
    expect(puts).toHaveLength(1);
    expect(puts[0]?.body).toMatchObject({ compute: { maxVms: 12 } });
  });

  test('CheckQuota reports whether a request fits', async ({ page }) => {
    const mock = await openLifecycle(page, { quotaAvailable: false });
    await lookUp(page);
    await page.getByLabel('Resource').fill('vcpus');
    await page.getByLabel('Amount').fill('64');
    await page.getByRole('button', { name: 'Check quota' }).click();
    await expect(page.getByTestId('quota-check-result')).toHaveText('Not available: quota exceeded');
    const posts = called(mock, 'POST', '/tenant-abc-123/quota-check');
    expect(posts).toHaveLength(1);
    expect(posts[0]?.body).toEqual({ resource: 'vcpus', amount: 64 });
  });

  test('Sync triggers a tenant sync', async ({ page }) => {
    const mock = await openLifecycle(page);
    await page.getByRole('button', { name: 'Sync tenants' }).click();
    await expect(page.getByRole('status')).toHaveText('Tenant sync started');
    expect(called(mock, 'POST', '/sync')).toHaveLength(1);
  });

  test('RotateTenantDEK asks for confirmation first', async ({ page }) => {
    const mock = await openLifecycle(page);
    await lookUp(page);
    await page.getByRole('button', { name: 'Rotate DEK' }).click();
    expect(called(mock, 'POST', '/tenant-abc-123/dek/rotate')).toHaveLength(0);
    await confirmDialog(page, 'Rotate tenant DEK', 'Rotate');
    await expect(page.getByRole('status')).toHaveText('DEK rotated to version 2');
    await expect(page.getByTestId('dek-version')).toHaveText('2');
    expect(called(mock, 'POST', '/tenant-abc-123/dek/rotate')).toHaveLength(1);
  });

  test('GetTenantDEKStatus shows the DEK version', async ({ page }) => {
    const mock = await openLifecycle(page);
    await lookUp(page);
    await page.getByRole('button', { name: 'Load DEK status' }).click();
    await expect(page.getByTestId('dek-status')).toContainText('AES-256-GCM');
    await expect(page.getByTestId('dek-version')).toHaveText('1');
    expect(called(mock, 'GET', '/tenant-abc-123/dek')).toHaveLength(1);
  });
});
