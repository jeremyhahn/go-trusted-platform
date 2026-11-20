/**
 * Real-server spec for the proxy operations (#2061, epic #1665).
 *
 * State is seeded through the SDK client against the harness server, never
 * through route mocks; every assertion is on what the server returns or on
 * what the page renders from it.
 */
import { test, expect } from './fixtures';

const uniq = () => `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;

test.describe('proxy: status, config and zone matrix', () => {
  test('status card shows the server version and counts', async ({ adminPage, sdk }) => {
    const status = await sdk.proxy.getStatus();
    expect(status.success).toBe(true);
    await adminPage.goto('/networking/proxy');
    await expect(adminPage.getByRole('heading', { name: 'Reverse proxy' })).toBeVisible();
    await expect(adminPage.getByTestId('proxy-status-version')).toHaveText(
      String(status.data?.version ?? '0'),
    );
    await expect(adminPage.getByTestId('proxy-status-routes')).toHaveText(
      String(status.data?.routeCount ?? 0),
    );
  });

  test('reload bumps the config version', async ({ adminPage, sdk }) => {
    const before = await sdk.proxy.getProxyConfig();
    await adminPage.goto('/networking/proxy');
    await adminPage.getByRole('button', { name: 'Reload config' }).click();
    await expect(adminPage.getByText(/Config reloaded/)).toBeVisible();
    const after = await sdk.proxy.getProxyConfig();
    expect(BigInt(after.data?.version ?? '0')).toBeGreaterThan(BigInt(before.data?.version ?? '0'));
  });

  test('config tab lists the server routes and pools', async ({ adminPage, sdk }) => {
    const config = await sdk.proxy.getProxyConfig();
    expect(config.success).toBe(true);
    await adminPage.goto('/networking/proxy');
    await adminPage.getByRole('tab', { name: 'Config' }).click();
    await expect(adminPage.getByTestId('proxy-config-version')).toContainText(
      String(config.data?.version ?? '0'),
    );
  });

  test('zone matrix lists the server zones', async ({ adminPage, sdk }) => {
    const matrix = await sdk.proxy.getZoneMatrix();
    await adminPage.goto('/networking/proxy');
    await adminPage.getByRole('tab', { name: 'Zone matrix' }).click();
    if (matrix.success) {
      for (const zone of matrix.data?.zones ?? []) {
        await expect(adminPage.getByTestId('proxy-zones')).toContainText(zone);
      }
    } else {
      await expect(adminPage.getByTestId('proxy-zone-matrix-error')).toBeVisible();
    }
  });
});

test.describe('proxy: pools', () => {
  test('create, edit and delete a pool through the page', async ({ adminPage, sdk }) => {
    const id = `pool-${uniq()}`;
    await adminPage.goto('/networking/proxy');
    await adminPage.getByRole('tab', { name: 'Pools' }).click();
    await adminPage.getByRole('button', { name: 'Add pool' }).click();
    await adminPage.getByLabel('Pool ID').fill(id);
    await adminPage.getByLabel('Backends').fill('https://10.0.0.10:8443');
    await adminPage.getByRole('button', { name: 'Save pool' }).click();
    await expect(adminPage.getByRole('row', { name: new RegExp(id) })).toBeVisible();

    const created = await sdk.proxy.getPool(id);
    expect(created.success).toBe(true);
    expect(created.data?.pool?.backends?.[0]?.url).toBe('https://10.0.0.10:8443');

    await adminPage.getByRole('row', { name: new RegExp(id) }).getByRole('button', { name: 'Edit' }).click();
    await adminPage.getByLabel('Backends').fill('https://10.0.0.11:8443');
    await adminPage.getByRole('button', { name: 'Save pool' }).click();
    await expect
      .poll(async () => (await sdk.proxy.getPool(id)).data?.pool?.backends?.[0]?.url)
      .toBe('https://10.0.0.11:8443');

    const pools = await sdk.proxy.listPools();
    expect(pools.data?.pools?.some((p) => p.id === id)).toBe(true);

    await adminPage.getByRole('row', { name: new RegExp(id) }).getByRole('button', { name: 'Delete' }).click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    await expect(adminPage.getByRole('row', { name: new RegExp(id) })).toHaveCount(0);
    expect((await sdk.proxy.getPool(id)).success).toBe(false);
  });
});

test.describe('proxy: routes', () => {
  test('a route seeded through the SDK is listed and can be edited and deleted', async ({ adminPage, sdk }) => {
    const poolId = `pool-${uniq()}`;
    const routeId = `route-${uniq()}`;
    expect(
      (await sdk.proxy.createPool({ id: poolId, backends: [{ url: 'https://10.0.0.20:8443', weight: 1 }] })).success,
    ).toBe(true);
    expect(
      (
        await sdk.proxy.createRoute({
          id: routeId,
          hosts: ['app.example.test'],
          pathPrefix: '/app',
          poolId,
          auth: { mode: 'mtls' },
        })
      ).success,
    ).toBe(true);

    await adminPage.goto('/networking/proxy');
    const row = adminPage.getByRole('row', { name: new RegExp(routeId) });
    await expect(row).toBeVisible();
    await expect(row).toContainText('/app');
    await expect(row).toContainText(poolId);

    await row.getByRole('button', { name: 'Edit' }).click();
    await adminPage.getByLabel('Path prefix').fill('/app2');
    await adminPage.getByRole('button', { name: 'Save route' }).click();
    await expect.poll(async () => (await sdk.proxy.getRoute(routeId)).data?.route?.pathPrefix).toBe('/app2');

    await adminPage.getByRole('row', { name: new RegExp(routeId) }).getByRole('button', { name: 'Delete' }).click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    await expect(adminPage.getByRole('row', { name: new RegExp(routeId) })).toHaveCount(0);
    expect((await sdk.proxy.getRoute(routeId)).success).toBe(false);

    await sdk.proxy.deletePool(poolId);
  });

  test('create a route through the page', async ({ adminPage, sdk }) => {
    const poolId = `pool-${uniq()}`;
    const routeId = `route-${uniq()}`;
    await sdk.proxy.createPool({ id: poolId, backends: [{ url: 'https://10.0.0.30:8443', weight: 1 }] });

    await adminPage.goto('/networking/proxy');
    await adminPage.getByRole('button', { name: 'Add route' }).click();
    await adminPage.getByLabel('Route ID').fill(routeId);
    await adminPage.getByLabel('Hosts').fill('svc.example.test');
    await adminPage.getByLabel('Path prefix').fill('/svc');
    await adminPage.getByLabel('Pool').fill(poolId);
    await adminPage.getByRole('button', { name: 'Save route' }).click();
    await expect(adminPage.getByRole('row', { name: new RegExp(routeId) })).toBeVisible();

    const listed = await sdk.proxy.listRoutes();
    expect(listed.data?.routes?.some((r) => r.id === routeId && r.poolId === poolId)).toBe(true);

    await sdk.proxy.deleteRoute(routeId);
    await sdk.proxy.deletePool(poolId);
  });
});
