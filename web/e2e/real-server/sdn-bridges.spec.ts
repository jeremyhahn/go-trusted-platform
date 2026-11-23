import type { Locator, Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The SDN page's bridge actions and the ports page's Port Statistics action
 * against the real platformd (#2064, epic #1665). No page.route mocks: each
 * assertion compares the page with what the server answered. Details reads a
 * bridge through GetBridge, Delete removes it through DeleteBridge after a
 * confirm, and Port Statistics is gated on its stats route; each control
 * carries the server's capability answer for its op.
 */

/** The reason the capability gate shows for an op the server does not list. */
const NOT_OFFERED = 'not offered by this server';

const BRIDGES_PATH = '/api/v1/sdn/bridges';

const CREATE_BRIDGE = 'POST /api/v1/sdn/bridges';
const GET_BRIDGE = 'GET /api/v1/sdn/bridges/{name}';
const DELETE_BRIDGE = 'DELETE /api/v1/sdn/bridges/{name}';
const PORT_STATS = 'GET /api/v1/sdn/bridges/{name}/ports/{port}/stats';

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
    await expect(control).toBeDisabled();
    await expect(control).toHaveAttribute('title', cap ? (cap.reason ?? '') : NOT_OFFERED);
  }
}

function isEnabled(listed: Map<string, Capability>, op: string): boolean {
  return listed.get(op)?.enabled === true;
}

test.describe('SDN bridges', () => {
  test('each bridge row gates Details and Delete on the server capabilities', async ({
    adminPage,
    sdk,
  }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (res.data?.capabilities ?? []).map((c) => [c.op, c]),
    );

    const bridgesRes = apiResponse(adminPage, BRIDGES_PATH);
    await adminPage.goto('/networking/sdn');
    const bridges = await bridgesRes;

    if (!bridges.ok()) {
      // No SDN service (503) or another refusal: the page lists no bridge and
      // offers no bridge action.
      await expect(adminPage.getByText('No networks found')).toBeVisible(SETTLED);
      await expect(adminPage.getByRole('button', { name: /^Details / })).toHaveCount(0);
      return;
    }

    const listedBridges =
      unwrapPayload<{ bridges?: Array<{ id: string; config?: { name?: string } }> }>(
        await bridges.json(),
      ).bridges ?? [];
    const first = listedBridges[0];
    if (!first) {
      await expect(adminPage.getByText('No networks found')).toBeVisible();
      return;
    }
    const name = first.config?.name || first.id;
    await expectGated(adminPage.getByRole('button', { name: `Details ${name}` }), GET_BRIDGE, listed);
    await expectGated(adminPage.getByRole('button', { name: `Delete ${name}` }), DELETE_BRIDGE, listed);
  });

  test('a seeded bridge reads in Details, its port gates Port Statistics, and Delete removes it', async ({
    adminPage,
    sdk,
  }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (res.data?.capabilities ?? []).map((c) => [c.op, c]),
    );
    const probe = await sdk.sdn.listBridges();
    if (!probe.success || !isEnabled(listed, CREATE_BRIDGE) || !isEnabled(listed, GET_BRIDGE)) {
      // The server offers no SDN bridge create or read: nothing to seed. The
      // page still loads and shows its bridge list card.
      await adminPage.goto('/networking/sdn');
      await expect(adminPage.getByText('Virtual Networks')).toBeVisible(SETTLED);
      return;
    }

    const name = `e2e-br-${Date.now().toString(36)}`;
    const created = await sdk.sdn.createBridge({ config: { name } });
    expect(created.success, JSON.stringify(created.error)).toBeTruthy();
    const bridgeId = created.data?.bridge?.id ?? name;
    let portId: string | undefined;
    try {
      const added = await sdk.sdn.addPort({ bridgeId, config: { name: 'e2e-p1' } });
      expect(added.success, JSON.stringify(added.error)).toBeTruthy();
      portId = added.data?.port?.id ?? 'e2e-p1';

      const bridgesRes = apiResponse(adminPage, BRIDGES_PATH);
      await adminPage.goto('/networking/sdn');
      await bridgesRes;

      await adminPage.getByRole('button', { name: `Details ${name}` }).click();
      await expect(adminPage.getByTestId('sdn-bridge-detail')).toContainText(name, SETTLED);
      await adminPage.getByRole('button', { name: 'Close' }).first().click();

      // The ports page shows the first bridge the server lists; check the
      // seeded port's menu when the seeded bridge is first.
      const portsRes = apiResponse(adminPage, BRIDGES_PATH);
      await adminPage.goto('/networking/ports');
      const firstOnPorts = unwrapPayload<{ bridges?: Array<{ id: string }> }>(
        await (await portsRes).json(),
      ).bridges?.[0]?.id;
      if (firstOnPorts === bridgeId) {
        const row = adminPage.getByRole('row').filter({ hasText: 'e2e-p1' }).first();
        await expect(row).toBeVisible(SETTLED);
        await row.getByRole('button', { name: 'Open menu' }).click();
        await expectGated(
          adminPage.getByRole('menuitem', { name: 'Port Statistics' }),
          PORT_STATS,
          listed,
        );
        await adminPage.keyboard.press('Escape');
      }

      if (isEnabled(listed, DELETE_BRIDGE)) {
        const again = apiResponse(adminPage, BRIDGES_PATH);
        await adminPage.goto('/networking/sdn');
        await again;
        const removed = await sdk.sdn.deletePort(bridgeId, portId);
        expect(removed.success, JSON.stringify(removed.error)).toBeTruthy();
        portId = undefined;

        await adminPage.getByRole('button', { name: `Delete ${name}` }).click();
        const dialog = adminPage.getByRole('dialog');
        await expect(dialog).toContainText(`Delete bridge ${name}?`);
        const relisted = apiResponse(adminPage, BRIDGES_PATH);
        await dialog.getByRole('button', { name: 'Delete', exact: true }).click();
        await relisted;
        await expect(adminPage.getByRole('row').filter({ hasText: name })).toHaveCount(0, SETTLED);
      }
    } finally {
      if (portId) await sdk.sdn.deletePort(bridgeId, portId);
      const still = await sdk.sdn.getBridge(bridgeId);
      if (still.success) await sdk.sdn.deleteBridge(bridgeId, true);
    }
  });
});
