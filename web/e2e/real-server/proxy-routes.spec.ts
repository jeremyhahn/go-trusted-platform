import type { Locator, Page, Response } from '@playwright/test';
import type { ApiResponse, CapabilitiesResponse, Capability, ProxyRoute } from 'trusted-platform-sdk';
import { expect, expectProxyFailsClosed, test } from './fixtures';
import { unwrapPayload, wireCount } from './fixtures/wire';

/**
 * Proxy routes page against the real platformd (#2061, epic #1665).
 *
 * Covers ListRoutes, GetRoute, CreateRoute, UpdateRoute, DeleteRoute,
 * GetProxyStatus and ReloadProxyConfig with no route mocks: every case reads
 * the server's capability answer first and asserts the enabled control or
 * the disabled one with the server's reason. The seeded pool and route come
 * from platformd.test.yaml (pool control-plane-console, route console).
 *
 * The proxy API is system-tenant only (pkg/webservice/v1/router.go,
 * proxyRoutes requires the system tenant), so the cases run as the
 * system-tenant admin (systemAdminPage, systemSdk), and one case asserts a
 * tenant admin is refused with 403. Without a scope-authorized session
 * (proxyAuthorized false) the system-admin cases assert the proxy's 403
 * fail-closed guard (requireScope) for every enabled op instead.
 */

/** The data of a successful SDK answer; fails the test on an error answer. */
function sdkData<T>(res: ApiResponse<T>, what: string): T {
  expect(res.success, `${what}: ${JSON.stringify(res.error)}`).toBeTruthy();
  if (res.data === undefined || res.data === null) throw new Error(`${what}: no data`);
  return res.data;
}

/** The capability of op as the server answered it (absent = off). */
function capabilityOf(caps: CapabilitiesResponse, op: string): Capability {
  return caps.capabilities.find((c) => c.op === op) ?? { op, kind: 'route', enabled: false };
}

/** Waits for the page's own request of method whose path matches. */
function apiResponse(page: Page, method: string, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && path.test(new URL(r.url()).pathname),
  );
}

/** The value the status card shows next to its term. */
function statusValue(card: Locator, term: string): Locator {
  return card.locator('dt', { hasText: new RegExp(`^${term}$`) }).locator('xpath=following-sibling::dd[1]');
}

/** A disabled gated control carries the capability's reason as its title. */
async function expectGatedOff(control: Locator, cap: Capability): Promise<void> {
  await expect(control).toBeDisabled();
  if (cap.reason) await expect(control).toHaveAttribute('title', cap.reason);
}

const LIST = 'GET /api/v1/proxy/routes';
const STATUS = 'GET /api/v1/proxy/status';
const RELOAD = 'POST /api/v1/proxy/reload';
const CREATE = 'POST /api/v1/proxy/routes';
const UPDATE = 'PUT /api/v1/proxy/routes/{id}';
const DELETE = 'DELETE /api/v1/proxy/routes/{id}';

test.describe('proxy routes against the real platformd (#2061)', () => {
  test('lists the routes the server answers', async ({ systemAdminPage: adminPage, systemSdk: sdk, proxyAuthorized }) => {
    const caps = sdkData(await sdk.capabilities.list(), 'capabilities');
    const on = (op: string) => capabilityOf(caps, op);
    if (!proxyAuthorized) {
      await expectProxyFailsClosed(adminPage.context().request, [LIST].filter((op) => on(op).enabled));
      await adminPage.goto('/networking/proxy');
      await expect(adminPage.locator('[data-testid^="proxy-route-"]')).toHaveCount(0);
      return;
    }

    if (!on(LIST).enabled) {
      await adminPage.goto('/networking/proxy');
      await expect(adminPage.getByTestId('proxy-not-enabled')).toBeVisible();
      return;
    }

    const listed = apiResponse(adminPage, 'GET', /\/api\/v1\/proxy\/routes$/);
    await adminPage.goto('/networking/proxy');
    const r = await listed;
    expect(r.ok(), `${r.url()} answered ${r.status()}`).toBeTruthy();
    const routes = unwrapPayload<{ routes?: ProxyRoute[] }>(await r.json()).routes ?? [];

    for (const route of routes) {
      await expect(adminPage.getByTestId(`proxy-route-${route.id ?? ''}`)).toBeVisible();
    }
    const seeded = adminPage.getByTestId('proxy-route-console');
    await expect(seeded).toBeVisible();
    await expect(seeded).toContainText('control-plane-console');
    await expect(seeded).toContainText('public');
  });

  test('shows the status the server answers and reloads it', async ({ systemAdminPage: adminPage, systemSdk: sdk, proxyAuthorized }) => {
    const caps = sdkData(await sdk.capabilities.list(), 'capabilities');
    const on = (op: string) => capabilityOf(caps, op);
    if (!proxyAuthorized) {
      await expectProxyFailsClosed(adminPage.context().request, [STATUS, RELOAD].filter((op) => on(op).enabled));
      return;
    }

    await adminPage.goto('/networking/proxy');

    if (on(STATUS).enabled) {
      const status = sdkData(await sdk.proxy.getStatus(), 'proxy status');
      const card = adminPage.getByTestId('proxy-status');
      await expect(statusValue(card, 'Routes')).toHaveText(String(wireCount(status.routeCount ?? 0)));
      await expect(statusValue(card, 'Pools')).toHaveText(String(wireCount(status.poolCount ?? 0)));
    }

    const reload = adminPage.getByRole('button', { name: 'Reload config' });
    if (!on(RELOAD).enabled) {
      await expectGatedOff(reload, on(RELOAD));
      return;
    }
    const reloaded = apiResponse(adminPage, 'POST', /\/api\/v1\/proxy\/reload$/);
    await reload.click();
    const r = await reloaded;
    expect(r.ok(), `${r.url()} answered ${r.status()}`).toBeTruthy();
  });

  test('creates, edits and deletes a route', async ({ systemAdminPage: adminPage, systemSdk: sdk, proxyAuthorized }) => {
    const caps = sdkData(await sdk.capabilities.list(), 'capabilities');
    const on = (op: string) => capabilityOf(caps, op);
    if (!proxyAuthorized) {
      await expectProxyFailsClosed(adminPage.context().request, [CREATE, UPDATE, DELETE].filter((op) => on(op).enabled));
      return;
    }

    await adminPage.goto('/networking/proxy');

    if (!on(CREATE).enabled) {
      await expectGatedOff(adminPage.getByRole('button', { name: 'New route' }), on(CREATE));
      return;
    }
    if (!on(UPDATE).enabled || !on(DELETE).enabled) {
      const seeded = adminPage.getByTestId('proxy-route-console');
      if (!on(UPDATE).enabled) {
        await expectGatedOff(seeded.getByRole('button', { name: 'Edit console' }), on(UPDATE));
      }
      if (!on(DELETE).enabled) {
        await expectGatedOff(seeded.getByRole('button', { name: 'Delete console' }), on(DELETE));
      }
      return;
    }

    const id = `e2e-${Date.now()}`;
    try {
      await adminPage.getByRole('button', { name: 'New route' }).click();
      const dialog = adminPage.getByRole('dialog');
      await dialog.getByLabel('Route ID').fill(id);
      await dialog.getByLabel('Hosts').fill('e2e.example');
      await dialog.getByLabel('Path prefix').fill('/e2e');
      await dialog.getByLabel('Pool ID').fill('control-plane-console');
      await dialog.getByLabel('Auth mode').selectOption('public');
      await dialog.getByRole('button', { name: 'Save' }).click();

      const row = adminPage.getByTestId(`proxy-route-${id}`);
      await expect(row).toBeVisible();
      const created = sdkData(await sdk.proxy.getRoute(id), `getRoute(${id})`);
      expect(created.route?.id).toBe(id);
      expect(created.route?.poolId).toBe('control-plane-console');

      await row.getByRole('button', { name: `Edit ${id}` }).click();
      const editor = adminPage.getByRole('dialog');
      await expect(editor.getByLabel('Path prefix')).toHaveValue('/e2e');
      await editor.getByLabel('Path prefix').fill('/e2e2');
      await editor.getByRole('button', { name: 'Save' }).click();
      await expect(editor).toBeHidden();
      const updated = sdkData(await sdk.proxy.getRoute(id), `getRoute(${id})`);
      expect(JSON.stringify(updated.route)).toContain('/e2e2');

      await row.getByRole('button', { name: `Delete ${id}` }).click();
      const confirm = adminPage.getByRole('dialog').filter({ hasText: 'Delete route' });
      await confirm.getByRole('button', { name: 'Delete', exact: true }).click();
      await expect(row).toHaveCount(0);
    } finally {
      const left = await sdk.proxy.getRoute(id);
      if (left.success && left.data?.route) await sdk.proxy.deleteRoute(id);
    }
  });

  test('a tenant admin is refused the proxy routes', async ({ adminPage }) => {
    const res = await adminPage.context().request.get('/api/v1/proxy/routes', { failOnStatusCode: false });
    expect(res.status()).toBe(403);
  });
});
