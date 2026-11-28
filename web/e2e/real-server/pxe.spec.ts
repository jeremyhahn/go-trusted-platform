import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The PXE page and the PXE device page against the real platformd (#2062,
 * epic #1665). No page.route mocks: the test daemon config seeds no PXE
 * service, so each assertion compares the page with what the server answered
 * the page itself, not with a fixed state.
 */

/** The reason the capability gate shows for an op the server does not list. */
const NOT_OFFERED = 'not offered by this server';

/** Waits for the page's own GET on exactly this path. */
function apiResponse(page: Page, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path,
  );
}

test.describe('PXE page', () => {
  test('the PXE page shows what the server answers for its devices', async ({ adminPage }) => {
    const devicesRes = apiResponse(adminPage, '/api/v1/pxe/devices');
    const statusRes = apiResponse(adminPage, '/api/v1/pxe/status');
    await adminPage.goto('/networking/pxe');
    const devices = await devicesRes;
    const status = await statusRes;

    if (devices.ok() && status.ok()) {
      const body = unwrapPayload<{ devices?: Array<{ macAddress: string }> }>(await devices.json());
      const listed = body.devices ?? [];
      await expect(adminPage.getByText('All Devices', { exact: true })).toBeVisible();
      // The All Devices table is the page's last table.
      const rows = adminPage.getByRole('table').last().locator('tbody tr');
      if (listed.length === 0) {
        await expect(rows).toHaveCount(1);
        await expect(rows.first()).toContainText('No devices found');
      } else {
        await expect(rows).toHaveCount(listed.length);
        for (const device of listed) {
          await expect(rows.filter({ hasText: device.macAddress })).toHaveCount(1);
        }
      }
    } else {
      // A refused read: the service-unavailable state (503) or the error state.
      await expect(
        adminPage.getByText(/not configured on this node|Error Loading PXE Boot/).first(),
      ).toBeVisible();
      await expect(adminPage.getByText('All Devices', { exact: true })).toHaveCount(0);
    }
  });
});

test.describe('PXE device page', () => {
  test('the PXE device page gates its controls on the server\'s capabilities', async ({
    adminPage,
    sdk,
  }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map((res.data?.capabilities ?? []).map((c) => [c.op, c]));

    await adminPage.goto('/networking/pxe/devices/02:00:00:00:00:01');
    for (const [name, op] of [
      ['Start PXE service', 'POST /api/v1/pxe/start'],
      ['Stop PXE service', 'POST /api/v1/pxe/stop'],
    ] as const) {
      const button = adminPage.getByRole('button', { name, exact: true });
      const cap = listed.get(op);
      const enabled = cap?.enabled === true;
      await expect(button).toHaveAttribute('data-capability-op', op);
      await expect(button).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
      if (!enabled) {
        await expect(button).toBeDisabled();
        await expect(button).toHaveAttribute('title', cap ? (cap.reason ?? '') : NOT_OFFERED);
      }
    }
  });
});
