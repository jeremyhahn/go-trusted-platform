import type { Locator, Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The SDN ports page against the real platformd (#2064, epic #1665). No
 * page.route mocks: each assertion compares the page with what the server
 * answered the page itself. Without an SDN service platformd answers 503 and
 * the page says SDN is not configured; with one, the spec seeds its own bridge
 * and port, checks the Gated controls of the Port State and Port
 * Authentication dialogs against the server's capabilities, and removes the
 * bridge again. It never clicks Apply, Authenticate or Revoke.
 */

/** The reason the capability gate shows for an op the server does not list. */
const NOT_OFFERED = 'not offered by this server';

const BRIDGES_PATH = '/api/v1/sdn/bridges';

/** The SDK retries a 5xx read three times with backoff before the page shows it. */
const SETTLED = { timeout: 20_000 };

type Capability = { op: string; enabled?: boolean; reason?: string };

/** Waits for the page's own GET on exactly this path. */
function apiResponse(page: Page, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path,
  );
}

/** Asserts a Gated button carries the op and the server's answer for it. */
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

test.describe('SDN ports page', () => {
  test('the ports page shows what the server answers for its bridges', async ({ adminPage }) => {
    const bridgesRes = apiResponse(adminPage, BRIDGES_PATH);
    await adminPage.goto('/networking/ports');
    const bridges = await bridgesRes;

    if (bridges.status() === 503) {
      await expect(adminPage.getByTestId('sdn-not-configured')).toBeVisible(SETTLED);
      await expect(adminPage.getByText('Error Loading Ports')).toHaveCount(0);
      return;
    }

    if (!bridges.ok()) {
      // Any other refused bridges read shows the server's message in an alert.
      await expect(adminPage.getByRole('alert').first()).toBeVisible(SETTLED);
      await expect(adminPage.getByText('Error Loading Ports')).toBeVisible();
      return;
    }

    await expect(adminPage.getByRole('heading', { name: 'SDN Ports' })).toBeVisible();
  });

  test("the Port State and Port Authentication dialogs gate their controls on the server's capabilities", async ({
    adminPage,
    sdk,
  }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (res.data?.capabilities ?? []).map((c) => [c.op, c]),
    );

    const probe = await sdk.sdn.listBridges();
    if (!probe.success) {
      // No SDN service (503) or another refusal: the page says so and offers
      // no port dialogs.
      const bridgesRes = apiResponse(adminPage, BRIDGES_PATH);
      await adminPage.goto('/networking/ports');
      const bridges = await bridgesRes;
      if (bridges.status() === 503) {
        await expect(adminPage.getByTestId('sdn-not-configured')).toBeVisible(SETTLED);
      } else {
        await expect(adminPage.getByRole('alert').first()).toBeVisible(SETTLED);
      }
      await expect(adminPage.getByRole('button', { name: 'Open menu' })).toHaveCount(0);
      return;
    }

    const name = `e2e-br-${Date.now().toString(36)}`;
    const created = await sdk.sdn.createBridge({ config: { name } });
    expect(created.success, JSON.stringify(created.error)).toBeTruthy();
    const bridgeId = created.data?.bridge?.id ?? name;
    try {
      const added = await sdk.sdn.addPort({ bridgeId, config: { name: 'e2e-p1' } });
      expect(added.success, JSON.stringify(added.error)).toBeTruthy();

      // The page shows the first bridge the server lists; it has no bridge
      // picker. Use the seeded port when the seeded bridge is first, else the
      // first port of the first bridge (read only: no write is clicked).
      const bridgesRes = apiResponse(adminPage, BRIDGES_PATH);
      await adminPage.goto('/networking/ports');
      const listedBridges = unwrapPayload<{ bridges?: Array<{ id: string }> }>(
        await (await bridgesRes).json(),
      ).bridges ?? [];
      const first = listedBridges[0]?.id;
      let portName = 'e2e-p1';
      if (first !== bridgeId) {
        const ports = first ? await sdk.sdn.listPorts({ bridgeId: first }) : undefined;
        const port = ports?.data?.ports?.[0];
        if (!port) {
          await expect(adminPage.getByRole('heading', { name: 'SDN Ports' })).toBeVisible();
          return;
        }
        portName = port.config?.name || 'port-0';
      }

      const row = adminPage.getByRole('row').filter({ hasText: portName }).first();
      await expect(row).toBeVisible();

      await row.getByRole('button', { name: 'Open menu' }).click();
      await adminPage.getByRole('menuitem', { name: 'Port State' }).click();
      const stateDialog = adminPage.getByRole('dialog', { name: `Port state: ${portName}` });
      await expect(stateDialog).toBeVisible();
      await expectGated(
        stateDialog.getByRole('button', { name: 'Refresh', exact: true }),
        'GET /api/v1/sdn/bridges/{name}/ports/{port}/state',
        listed,
      );
      await expectGated(
        stateDialog.getByRole('button', { name: 'Apply', exact: true }),
        'PUT /api/v1/sdn/bridges/{name}/ports/{port}/state',
        listed,
      );
      await adminPage.keyboard.press('Escape');
      await expect(stateDialog).toHaveCount(0);

      await row.getByRole('button', { name: 'Open menu' }).click();
      await adminPage.getByRole('menuitem', { name: 'Port Authentication' }).click();
      const authDialog = adminPage.getByRole('dialog', { name: `Port authentication: ${portName}` });
      await expect(authDialog).toBeVisible();
      await expectGated(
        authDialog.getByRole('button', { name: 'Authenticate', exact: true }),
        'POST /api/v1/sdn/bridges/{name}/ports/{port}/auth',
        listed,
      );
      await expectGated(
        authDialog.getByRole('button', { name: 'Revoke', exact: true }),
        'DELETE /api/v1/sdn/bridges/{name}/ports/{port}/auth',
        listed,
      );
      await adminPage.keyboard.press('Escape');
    } finally {
      await sdk.sdn.deleteBridge(bridgeId, true);
    }
  });
});
