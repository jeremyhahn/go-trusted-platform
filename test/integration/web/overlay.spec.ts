/**
 * Overlay (VXLAN) operations against the real-server harness (#2059).
 *
 * No route is mocked: the VTEPs page reads and writes through the SDK client
 * against the running webservice. The session is the server-issued admin JWT
 * from E2E_ADMIN_JWT (fixtures/admin-session.fixture.ts). A server that runs no
 * overlay answers 404 or 503 on GET /api/v1/overlay/status; the specs skip there.
 */
import type { Page, Response } from '@playwright/test';
import { test, expect } from './fixtures/admin-session.fixture';

function overlayResponse(page: Page, method: string, route: string): Promise<Response> {
  return page.waitForResponse(
    (r) =>
      r.request().method() === method && new URL(r.url()).pathname.endsWith(`/v1/overlay${route}`),
  );
}

async function openOverlayPage(page: Page) {
  const [status, vteps, vnis, tunnels, macs] = await Promise.all([
    overlayResponse(page, 'GET', '/status'),
    overlayResponse(page, 'GET', '/vteps'),
    overlayResponse(page, 'GET', '/vnis'),
    overlayResponse(page, 'GET', '/tunnels'),
    overlayResponse(page, 'GET', '/macs'),
    page.goto('/networking/overlays/vteps'),
  ]);
  test.skip([404, 503].includes(status.status()), 'this server runs no overlay');
  // A 401/403 means the admin session was refused: that fails, it does not skip.
  expect(status.status(), 'GET overlay status').toBe(200);
  const lists: Array<[string, Response]> = [
    ['vteps', vteps],
    ['vnis', vnis],
    ['tunnels', tunnels],
    ['macs', macs],
  ];
  for (const [name, res] of lists) {
    expect(res.status(), `GET overlay ${name}`).toBe(200);
  }
  // The Refresh button is disabled while any list loads.
  await expect(page.getByRole('button', { name: 'Refresh' })).toBeEnabled();
}

test.describe('Overlay VTEPs page (real server)', () => {
  test('the page shows the status and the four lists', async ({ adminPage: page }) => {
    await openOverlayPage(page);

    const status = page.locator('[data-testid="overlay-status"]');
    await expect(status.locator('dl')).toContainText('VTEP IP');
    for (const id of ['vteps-table', 'vnis-table', 'tunnels-table', 'macs-table']) {
      await expect(page.locator(`[data-testid="${id}"]`)).toBeVisible();
    }
    // The lists have settled with 200, so no list error may show.
    for (const id of ['vteps-list-error', 'vnis-list-error', 'tunnels-list-error', 'macs-list-error']) {
      await expect(page.locator(`[data-testid="${id}"]`)).toHaveCount(0);
    }
  });

  test('a VTEP opens its detail', async ({ adminPage: page }) => {
    await openOverlayPage(page);

    const details = page
      .locator('[data-testid="vteps-table"] tbody')
      .getByRole('button', { name: /^Details / });
    // The Details count is read only after openOverlayPage: the VTEP list has settled.
    if ((await details.count()) === 0) {
      test.skip(true, 'no VTEPs on this server');
    }
    await details.first().click();
    await expect(page.getByRole('dialog')).toContainText('Tunnel endpoint details');
  });

  test('a tunnel opens its statistics', async ({ adminPage: page }) => {
    await openOverlayPage(page);

    const stats = page
      .locator('[data-testid="tunnels-table"]')
      .getByRole('button', { name: /^Stats / });
    // The Stats count is read only after openOverlayPage: the tunnel list has settled.
    if ((await stats.count()) === 0) {
      test.skip(true, 'no tunnels on this server');
    }
    await stats.first().click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Tunnel statistics');
    await expect(dialog).toContainText('Bytes sent');
  });

  test('forgetting an unknown MAC sends the DELETE and shows its success or refusal', async ({
    adminPage: page,
  }) => {
    await openOverlayPage(page);

    const form = page.locator('[data-testid="overlay-forget-mac"]');
    await form.getByLabel('MAC address').fill('02:00:00:00:e2:e2');
    await form.getByLabel('VNI').fill('16777000');
    await form.getByRole('button', { name: 'Forget MAC' }).click();

    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Forget MAC 02:00:00:00:e2:e2 on VNI 16777000?');
    const del = overlayResponse(page, 'DELETE', '/macs');
    const refresh = overlayResponse(page, 'GET', '/macs').catch(() => null);
    await dialog.getByRole('button', { name: 'Forget', exact: true }).click();

    const res = await del;
    const query = new URL(res.url()).searchParams;
    expect(query.get('mac')).toBe('02:00:00:00:e2:e2');
    expect(query.get('vni')).toBe('16777000');
    expect([401, 403]).not.toContain(res.status());

    const toasts = page.getByRole('region', { name: 'Notifications' });
    if (res.ok()) {
      await expect(toasts.getByText('MAC forgotten', { exact: true })).toBeVisible();
      await expect(dialog).toHaveCount(0);
      const refreshed = await refresh;
      expect(refreshed?.status()).toBe(200);
    } else {
      expect(res.status()).toBeGreaterThanOrEqual(400);
      await expect(toasts.getByText('Forget MAC failed', { exact: true })).toBeVisible();
      await expect(dialog).toBeVisible();
      await expect(toasts.getByText('MAC forgotten', { exact: true })).toHaveCount(0);
    }

    await expect(page.locator('[data-testid="macs-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="macs-list-error"]')).toHaveCount(0);
  });
});
