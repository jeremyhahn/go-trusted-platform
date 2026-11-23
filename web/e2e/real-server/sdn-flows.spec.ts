import type { Locator, Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The OpenFlow rules page against the real platformd (#2064, epic #1665). No
 * page.route mocks: each assertion compares the page with what the server
 * answered the page itself. Without an SDN service the bridges read is
 * refused and the page shows its error alert; with one, the spec checks the
 * Gated Flush flows header control, seeds its own bridge and flow, checks the
 * Gated Flow Statistics row action against the server's capabilities, and
 * removes the bridge again. It never clicks Flush.
 */

/** The reason the capability gate shows for an op the server does not list. */
const NOT_OFFERED = 'not offered by this server';

const BRIDGES_PATH = '/api/v1/sdn/bridges';
const FLUSH_OP = 'POST /api/v1/sdn/bridges/{name}/flows/flush';
const FLOW_STATS_OP = 'GET /api/v1/sdn/bridges/{name}/flows/{flow}/stats';

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
  control: Locator,
  op: string,
  listed: Map<string, Capability>,
): Promise<void> {
  const cap = listed.get(op);
  const enabled = cap?.enabled === true;
  await expect(control).toHaveAttribute('data-capability-op', op);
  await expect(control).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
  if (!enabled) {
    await expect(control).toHaveAttribute('title', cap ? (cap.reason ?? '') : NOT_OFFERED);
  }
}

test.describe('SDN flows page', () => {
  test('the flows page shows what the server answers and gates Flush flows', async ({ adminPage, sdk }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (res.data?.capabilities ?? []).map((c) => [c.op, c]),
    );

    const bridgesRes = apiResponse(adminPage, BRIDGES_PATH);
    await adminPage.goto('/networking/flows');
    const bridges = await bridgesRes;

    if (!bridges.ok()) {
      // No SDN service (503) or another refusal: the page shows its error
      // alert with a Retry, and no flow controls.
      await expect(adminPage.getByText('Error Loading Flows')).toBeVisible(SETTLED);
      await expect(adminPage.getByRole('button', { name: 'Retry' })).toBeVisible();
      await expect(adminPage.getByRole('button', { name: 'Flush flows' })).toHaveCount(0);
      return;
    }

    await expect(adminPage.getByRole('heading', { name: 'OpenFlow Rules' })).toBeVisible(SETTLED);
    await expectGated(adminPage.getByRole('button', { name: 'Flush flows' }), FLUSH_OP, listed);
  });

  test("the Flow Statistics row action is gated on the server's capabilities", async ({ adminPage, sdk }) => {
    const probe = await sdk.sdn.listBridges();
    if (!probe.success) {
      // No SDN service or another refusal: the page offers no flow rows.
      await adminPage.goto('/networking/flows');
      await expect(adminPage.getByText('Error Loading Flows')).toBeVisible(SETTLED);
      await expect(adminPage.getByRole('button', { name: 'Open menu' })).toHaveCount(0);
      return;
    }

    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (res.data?.capabilities ?? []).map((c) => [c.op, c]),
    );

    const name = `e2e-br-${Date.now().toString(36)}`;
    const created = await sdk.sdn.createBridge({ config: { name } });
    expect(created.success, JSON.stringify(created.error)).toBeTruthy();
    const bridgeId = created.data?.bridge?.id ?? name;
    try {
      const flowName = 'e2e-f1';
      const added = await sdk.sdn.addFlow({
        config: {
          bridgeId,
          priority: 100,
          match: {},
          actions: [{ type: 'FLOW_ACTION_OUTPUT' }],
          metadata: { name: flowName },
        },
      });
      expect(added.success, JSON.stringify(added.error)).toBeTruthy();

      // The page shows the first bridge the server lists; it has no bridge
      // picker. The row action is checked only when the seeded bridge is the
      // selected one (read only: no write is clicked).
      const bridgesRes = apiResponse(adminPage, BRIDGES_PATH);
      await adminPage.goto('/networking/flows');
      const listedBridges = unwrapPayload<{ bridges?: Array<{ id: string }> }>(
        await (await bridgesRes).json(),
      ).bridges ?? [];
      await expect(adminPage.getByRole('heading', { name: 'OpenFlow Rules' })).toBeVisible(SETTLED);
      if (listedBridges[0]?.id !== bridgeId) {
        return;
      }

      const row = adminPage.getByRole('row').filter({ hasText: flowName }).first();
      await expect(row).toBeVisible(SETTLED);
      await row.getByRole('button', { name: 'Open menu' }).click();
      await expectGated(
        adminPage.getByRole('menuitem', { name: 'Flow Statistics' }),
        FLOW_STATS_OP,
        listed,
      );
      await adminPage.keyboard.press('Escape');
    } finally {
      await sdk.sdn.deleteBridge(bridgeId, true);
    }
  });
});
