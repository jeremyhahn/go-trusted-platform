import { test, expect } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockRegistryApi, mockTenantApi } from './fixtures/api-mock';

test.describe('Container registry', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
    await mockTenantApi(page);
  });

  test('lists repository tags', async ({ page }) => {
    await mockRegistryApi(page, { repositories: { 'team/app': ['v1', 'latest'] } });

    await page.goto('/compute/registry');
    await page.getByLabel('Repository').fill('team/app');
    await page.getByRole('button', { name: /list tags/i }).click();

    await expect(page.getByRole('cell', { name: 'v1', exact: true })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'latest', exact: true })).toBeVisible();
  });

  test('shows an error for an unknown repository', async ({ page }) => {
    await mockRegistryApi(page, { repositories: {} });

    await page.goto('/compute/registry');
    await page.getByLabel('Repository').fill('missing');
    await page.getByRole('button', { name: /list tags/i }).click();

    await expect(page.getByText(/failed to list tags/i)).toBeVisible();
  });

  test('deletes a manifest after confirmation', async ({ page }) => {
    const state = await mockRegistryApi(page, { repositories: { app: ['v1', 'v2'] } });

    await page.goto('/compute/registry');
    await page.getByLabel('Repository').fill('app');
    await page.getByRole('button', { name: /list tags/i }).click();
    await page.getByRole('button', { name: 'Delete v1' }).click();

    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('app:v1');
    await dialog.getByRole('button', { name: 'Delete', exact: true }).click();

    await expect(dialog).toBeHidden();
    await expect(page.getByRole('cell', { name: 'v1', exact: true })).toHaveCount(0);
    await expect(page.getByRole('cell', { name: 'v2', exact: true })).toBeVisible();
    expect(state.deleted).toEqual(['app:v1']);
  });

  test('cancel in the confirm dialog deletes nothing', async ({ page }) => {
    const state = await mockRegistryApi(page, { repositories: { app: ['v1'] } });

    await page.goto('/compute/registry');
    await page.getByLabel('Repository').fill('app');
    await page.getByRole('button', { name: /list tags/i }).click();
    await page.getByRole('button', { name: 'Delete v1' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();

    await expect(page.getByRole('dialog')).toBeHidden();
    await expect(page.getByRole('cell', { name: 'v1', exact: true })).toBeVisible();
    expect(state.deleted).toEqual([]);
  });

  test('shows registry status', async ({ page }) => {
    await mockRegistryApi(page, {
      status: { Health: 1, Version: '2.3.4', ReadOnly: true, Components: [{ Name: 'storage', Status: 1 }] },
    });

    await page.goto('/compute/registry');

    const card = page.getByTestId('registry-status');
    await expect(card).toContainText('Healthy');
    await expect(card).toContainText('2.3.4');
    await expect(card).toContainText('Read-only');
  });

  test('shows a status error', async ({ page }) => {
    await mockRegistryApi(page, { statusError: { status: 500, error: 'registry not configured' } });

    await page.goto('/compute/registry');

    await expect(page.getByTestId('registry-status')).toContainText(/failed to load status/i);
  });
});
