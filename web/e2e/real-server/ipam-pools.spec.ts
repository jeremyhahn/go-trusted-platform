import type { Locator, Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';

/**
 * The SDN IPAM pools page against the real platformd (#2051, epic #1665). No
 * page.route mocks: each assertion compares the page with what the server
 * answered. Without an SDN gateway platformd refuses the pools read and the
 * page shows the error; with one, the spec seeds its own pool through the SDK,
 * checks every pool control's gate against the server's capabilities, opens
 * the pool's details, and deletes the pool again.
 */

/** The reason the capability gate shows for an op the server does not list. */
const NOT_OFFERED = 'not offered by this server';

const POOLS_PATH = '/api/v1/sdn/gateway/ipam/pools';

const LIST_POOLS = 'GET /api/v1/sdn/gateway/ipam/pools';
const CREATE_POOL = 'POST /api/v1/sdn/gateway/ipam/pools';
const GET_POOL = 'GET /api/v1/sdn/gateway/ipam/pools/{id}';
const UPDATE_POOL = 'PUT /api/v1/sdn/gateway/ipam/pools/{id}';
const DELETE_POOL = 'DELETE /api/v1/sdn/gateway/ipam/pools/{id}';
const LIST_ALLOCATIONS = 'GET /api/v1/sdn/gateway/ipam/allocations';

/** The SDK retries a 5xx read three times with backoff before the page shows it. */
const SETTLED = { timeout: 20_000 };

type Capability = { op: string; enabled?: boolean; reason?: string };

/** Waits for the page's own GET on exactly this path. */
function apiResponse(page: Page, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path,
  );
}

/** Asserts a Gated control carries the op and the server's answer for it. */
async function expectGated(
  button: Locator,
  op: string,
  listed: Map<string, Capability>,
): Promise<void> {
  const cap = listed.get(op);
  const enabled = cap?.enabled === true;
  await expect(button).toHaveAttribute('data-capability-op', op);
  await expect(button).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
  if (!enabled) {
    await expect(button).toBeDisabled();
    await expect(button).toHaveAttribute('title', cap ? (cap.reason ?? '') : NOT_OFFERED);
  }
}

test.describe('IPAM pools page', () => {
  test('the IPAM pools page shows what the server answers and gates Refresh and Create', async ({
    adminPage,
    sdk,
  }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map<string, Capability>((res.data?.capabilities ?? []).map((c) => [c.op, c]));

    const poolsRes = apiResponse(adminPage, POOLS_PATH);
    await adminPage.goto('/networking/ipam');
    const pools = await poolsRes;

    if (!pools.ok()) {
      // No SDN gateway (503) or another refusal: the page shows the error.
      await expect(adminPage.getByText('Error Loading IPAM Pools')).toBeVisible(SETTLED);
      return;
    }

    await expect(adminPage.getByRole('heading', { name: 'IPAM Pools' })).toBeVisible();
    await expectGated(adminPage.getByRole('button', { name: 'Refresh pools' }), LIST_POOLS, listed);
    await expectGated(adminPage.getByRole('button', { name: 'Create Pool' }), CREATE_POOL, listed);
  });

  test("a pool's row actions carry their gates and Details shows the pool the server answers", async ({
    adminPage,
    sdk,
  }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map<string, Capability>((res.data?.capabilities ?? []).map((c) => [c.op, c]));

    const probe = await sdk.sdn.listIPAMPools();
    if (!probe.success) {
      // No SDN gateway: no pools, so no row actions to check.
      const poolsRes = apiResponse(adminPage, POOLS_PATH);
      await adminPage.goto('/networking/ipam');
      await poolsRes;
      await expect(adminPage.getByText('Error Loading IPAM Pools')).toBeVisible(SETTLED);
      await expect(adminPage.getByRole('button', { name: 'Open menu' })).toHaveCount(0);
      return;
    }

    if (listed.get(CREATE_POOL)?.enabled !== true) {
      // The spec cannot seed a pool; the Create button says why.
      const poolsRes = apiResponse(adminPage, POOLS_PATH);
      await adminPage.goto('/networking/ipam');
      await poolsRes;
      await expectGated(adminPage.getByRole('button', { name: 'Create Pool' }), CREATE_POOL, listed);
      return;
    }

    const name = `e2e-pool-${Date.now().toString(36)}`;
    const cidr = '192.0.2.0/26';
    const created = await sdk.sdn.createIPAMPool({ name, cidr });
    expect(created.success, JSON.stringify(created.error)).toBeTruthy();
    const poolId = created.data?.id ?? '';
    expect(poolId).not.toBe('');

    try {
      const poolsRes = apiResponse(adminPage, POOLS_PATH);
      await adminPage.goto('/networking/ipam');
      expect((await poolsRes).ok()).toBeTruthy();

      await adminPage.getByPlaceholder('Search pools...').fill(name);
      const row = adminPage.getByRole('row').filter({ hasText: name });
      await expect(row).toHaveCount(1);

      await row.getByRole('button', { name: 'Open menu' }).click();
      const menu = adminPage.getByRole('menu');
      await expectGated(menu.getByRole('menuitem', { name: 'Edit' }), UPDATE_POOL, listed);
      await expectGated(menu.getByRole('menuitem', { name: 'Details' }), GET_POOL, listed);
      await expectGated(menu.getByRole('menuitem', { name: 'View Allocations' }), LIST_ALLOCATIONS, listed);
      await expectGated(menu.getByRole('menuitem', { name: 'Delete' }), DELETE_POOL, listed);

      if (listed.get(GET_POOL)?.enabled !== true) {
        await adminPage.keyboard.press('Escape');
        return;
      }

      await menu.getByRole('menuitem', { name: 'Details' }).click();
      const dialog = adminPage.getByRole('dialog');
      await expect(dialog.getByText(`Pool ${name}`)).toBeVisible();
      await expect(dialog.getByTestId('ipam-pool-detail')).toContainText(cidr, SETTLED);
    } finally {
      await sdk.sdn.deleteIPAMPool(poolId);
    }
  });
});
