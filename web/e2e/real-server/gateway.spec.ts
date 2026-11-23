import type { Locator, Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The gateway pages against the real platformd (#2051, epic #1665). No
 * page.route mocks and no writes: the test daemon config seeds no gateway
 * section, so each assertion compares the page with what the server answered
 * the page itself (503 not configured, or a list), not with a fixed state.
 */

/** The reason the capability gate shows for an op the server does not list. */
const NOT_OFFERED = 'not offered by this server';

const ALLOCATIONS = '/api/v1/gateway/ipam/allocations';

/** Waits for the page's own GET on exactly this path. */
function apiResponse(page: Page, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path,
  );
}

test.describe('Gateway pages', () => {
  test('the gateway page shows the reported gateways and the not-configured state the server answers', async ({
    adminPage,
  }) => {
    const stateRes = apiResponse(adminPage, '/api/v1/gateway/state');
    const statusRes = apiResponse(adminPage, '/api/v1/gateway/status');
    await adminPage.goto('/networking/gateway');
    const state = await stateRes;
    const status = await statusRes;

    if (state.ok()) {
      const body = unwrapPayload<{ gateways?: Array<{ gateway_id: string }> }>(await state.json());
      const reported = body.gateways ?? [];
      if (reported.length === 0) {
        await expect(adminPage.getByText('No gatewayd processes have reported yet', { exact: false })).toBeVisible();
      } else {
        for (const g of reported) {
          await expect(adminPage.getByText(g.gateway_id, { exact: true }).first()).toBeVisible();
        }
      }
    } else {
      await expect(adminPage.getByText('Failed to load:', { exact: false })).toBeVisible();
    }

    if (status.status() === 503) {
      await expect(adminPage.getByText('This node does not run gatewayd', { exact: false })).toBeVisible();
    }
  });

  test('the IPAM page shows the allocations the server answers', async ({ adminPage, sdk }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listCap = (res.data?.capabilities ?? []).find((c) => c.op === `GET ${ALLOCATIONS}`);

    const listRes = apiResponse(adminPage, ALLOCATIONS);
    await adminPage.goto('/networking/gateway/ipam');

    if (listCap?.enabled !== true) {
      const notEnabled = adminPage.getByTestId('gateway-ipam-not-enabled');
      await expect(notEnabled).toBeVisible();
      if (listCap?.reason) {
        await expect(notEnabled).toContainText(listCap.reason);
      }
      return;
    }

    const list = await listRes;
    if (list.status() === 503 || !list.ok()) {
      await expect(adminPage.getByTestId('gateway-allocations-error')).toBeVisible();
      await expect(adminPage.getByTestId('gateway-allocation-row')).toHaveCount(0);
      return;
    }

    const body = unwrapPayload<{ allocations?: Array<{ ip: string }> }>(await list.json());
    const listed = body.allocations ?? [];
    if (listed.length === 0) {
      await expect(adminPage.getByTestId('gateway-allocations-empty')).toHaveText('No allocations');
      return;
    }
    const rows = adminPage.getByTestId('gateway-allocation-row');
    await expect(rows).toHaveCount(listed.length);
    for (const a of listed) {
      await expect(rows.filter({ hasText: a.ip })).toHaveCount(1);
    }
  });

  test("the IPAM page gates Refresh, Filter, Allocate and Release on the server's capabilities", async ({
    adminPage,
    sdk,
  }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map((res.data?.capabilities ?? []).map((c) => [c.op, c]));

    const listRes = apiResponse(adminPage, ALLOCATIONS);
    await adminPage.goto('/networking/gateway/ipam');
    await expect(adminPage.getByRole('button', { name: 'Refresh', exact: true })).toBeVisible();
    if (listed.get(`GET ${ALLOCATIONS}`)?.enabled === true) {
      await listRes;
    }

    const checkGate = async (button: Locator, op: string) => {
      const cap = listed.get(op);
      const enabled = cap?.enabled === true;
      await expect(button).toHaveAttribute('data-capability-op', op);
      await expect(button).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
      if (!enabled) {
        // Allocate stays disabled until a pool is typed, so an offered
        // control is never asserted enabled here.
        await expect(button).toBeDisabled();
        await expect(button).toHaveAttribute('title', cap ? (cap.reason ?? '') : NOT_OFFERED);
      }
    };

    await checkGate(adminPage.getByRole('button', { name: 'Refresh', exact: true }), `GET ${ALLOCATIONS}`);
    await checkGate(adminPage.getByRole('button', { name: 'Filter', exact: true }), `GET ${ALLOCATIONS}`);
    await checkGate(adminPage.getByRole('button', { name: 'Allocate', exact: true }), `POST ${ALLOCATIONS}`);

    const rows = adminPage.getByTestId('gateway-allocation-row');
    if ((await rows.count()) > 0) {
      const release = rows.first().getByRole('button', { name: /^Release / });
      await checkGate(release, `DELETE ${ALLOCATIONS}`);
    }
  });
});
