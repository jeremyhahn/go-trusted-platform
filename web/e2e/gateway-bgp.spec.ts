import { test, expect } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockGatewayBgpApi, mockTenantApi } from './fixtures/api-mock';

const PAGE = '/networking/gateway/bgp';

test.describe('Gateway BGP and IPAM', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
    await mockTenantApi(page);
  });

  test('lists BGP peers', async ({ page }) => {
    await mockGatewayBgpApi(page, {
      peers: [{ address: '10.0.0.2', asn: 64513, state: 'established', prefixes_received: 4 }],
    });
    await page.goto(PAGE);

    const table = page.getByRole('table', { name: 'BGP peers' });
    const row = table.getByRole('row', { name: /10\.0\.0\.2/ });
    await expect(row).toBeVisible();
    await expect(row).toContainText('64513');
    await expect(row).toContainText('established');
    await expect(row).toContainText('4');
  });

  test('announces a prefix', async ({ page }) => {
    const { calls } = await mockGatewayBgpApi(page);
    await page.goto(PAGE);

    await page.getByLabel('Prefix', { exact: true }).fill('203.0.113.0/24');
    await page.getByLabel('Next hop').fill('10.0.0.1');
    await page.getByRole('button', { name: 'Announce' }).click();

    const table = page.getByRole('table', { name: 'Announced prefixes' });
    await expect(table.getByRole('row', { name: /203\.0\.113\.0\/24/ })).toBeVisible();
    expect(calls).toContainEqual(
      expect.objectContaining({
        method: 'POST',
        path: '/bgp/prefixes',
        body: { prefix: '203.0.113.0/24', next_hop: '10.0.0.1' },
      })
    );
  });

  test('withdraws a prefix after confirming', async ({ page }) => {
    const { calls } = await mockGatewayBgpApi(page, {
      prefixes: [{ prefix: '203.0.113.0/24', next_hop: '10.0.0.1' }],
    });
    await page.goto(PAGE);

    const table = page.getByRole('table', { name: 'Announced prefixes' });
    await table.getByRole('button', { name: 'Withdraw 203.0.113.0/24' }).click();

    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Withdraw 203.0.113.0/24');
    // Cancelling sends nothing.
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(0);

    await table.getByRole('button', { name: 'Withdraw 203.0.113.0/24' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();

    await expect(table.getByText('No announced prefixes.')).toBeVisible();
    expect(calls).toContainEqual(
      expect.objectContaining({
        method: 'DELETE',
        path: '/bgp/prefixes',
        query: { prefix: '203.0.113.0/24' },
      })
    );
  });

  test('allocates an IP', async ({ page }) => {
    const { calls } = await mockGatewayBgpApi(page, { nextIP: '10.0.0.11' });
    await page.goto(PAGE);

    await page.getByLabel('Pool ID').fill('prod-v4');
    await page.getByLabel('Hostname').fill('node-04');
    await page.getByRole('button', { name: 'Allocate' }).click();

    const table = page.getByRole('table', { name: 'IP allocations' });
    const row = table.getByRole('row', { name: /10\.0\.0\.11/ });
    await expect(row).toBeVisible();
    await expect(row).toContainText('node-04');
    expect(calls).toContainEqual(
      expect.objectContaining({
        method: 'POST',
        path: '/ipam/allocations',
        body: { pool_id: 'prod-v4', hostname: 'node-04' },
      })
    );
  });

  test('releases an IP after confirming', async ({ page }) => {
    const { calls } = await mockGatewayBgpApi(page, {
      allocations: [{ ip: '10.0.0.10', pool_id: 'prod-v4', hostname: 'node-03', status: 'active' }],
    });
    await page.goto(PAGE);

    const table = page.getByRole('table', { name: 'IP allocations' });
    await table.getByRole('button', { name: 'Release 10.0.0.10' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Release 10.0.0.10');
    await dialog.getByRole('button', { name: 'Confirm' }).click();

    await expect(table.getByText('No allocations.')).toBeVisible();
    expect(calls).toContainEqual(
      expect.objectContaining({
        method: 'DELETE',
        path: '/ipam/allocations',
        query: { ip: '10.0.0.10' },
      })
    );
  });

  test('lists IPAM allocations', async ({ page }) => {
    await mockGatewayBgpApi(page, {
      allocations: [
        { ip: '10.0.0.10', pool_id: 'prod-v4', hostname: 'node-03', status: 'active' },
        { ip: '10.0.0.12', pool_id: 'prod-v4', hostname: 'node-05', status: 'reserved' },
      ],
    });
    await page.goto(PAGE);

    const table = page.getByRole('table', { name: 'IP allocations' });
    await expect(table.getByRole('row', { name: /10\.0\.0\.10.*node-03/ })).toBeVisible();
    await expect(table.getByRole('row', { name: /10\.0\.0\.12.*node-05/ })).toBeVisible();
    await expect(table).toContainText('reserved');
  });

  test('shows the error when a list fails', async ({ page }) => {
    await page.route(/\/api\/v1\/gateway\/(bgp|ipam)\//, (route) =>
      route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'gateway is not running' }),
      })
    );
    await page.goto(PAGE);
    await expect(page.getByText('Could not load gateway data')).toBeVisible();
    await expect(page.getByText('gateway is not running')).toBeVisible();
  });
});
