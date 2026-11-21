/**
 * Overlay (VXLAN) operations against the real-server harness (#2059).
 *
 * No route is mocked: the VTEPs page reads and writes through the SDK client
 * against the running webservice. A server that runs no overlay answers
 * service unavailable, which the page shows as overlay-status-error; the specs
 * skip there.
 */
import type { Page } from '@playwright/test';
import { test, expect } from './fixtures/auth.fixture';

async function openOverlayPage(page: Page) {
  await page.goto('/networking/overlays/vteps');
  const status = page.locator('[data-testid="overlay-status"]');
  await expect(status).toBeVisible();
  const statusError = page.locator('[data-testid="overlay-status-error"]');
  if (await statusError.isVisible()) {
    const text = (await statusError.textContent()) ?? '';
    if (/unavailable/i.test(text)) {
      test.skip(true, 'this server runs no overlay');
    }
  }
}

test.describe('Overlay VTEPs page (real server)', () => {
  test('the page shows the status and the four lists', async ({ authenticatedPage: page }) => {
    await openOverlayPage(page);

    const status = page.locator('[data-testid="overlay-status"]');
    await expect(status.locator('dl')).toContainText('VTEP IP');
    for (const id of ['vteps-table', 'vnis-table', 'tunnels-table', 'macs-table']) {
      await expect(page.locator(`[data-testid="${id}"]`)).toBeVisible();
    }
    for (const id of ['vteps-list-error', 'vnis-list-error', 'tunnels-list-error', 'macs-list-error']) {
      await expect(page.locator(`[data-testid="${id}"]`)).toHaveCount(0);
    }
  });

  test('a VTEP opens its detail', async ({ authenticatedPage: page }) => {
    await openOverlayPage(page);

    const details = page
      .locator('[data-testid="vteps-table"] tbody')
      .getByRole('button', { name: /^Details / });
    if ((await details.count()) === 0) {
      test.skip(true, 'no VTEPs on this server');
    }
    await details.first().click();
    await expect(page.getByRole('dialog')).toContainText('Tunnel endpoint details');
  });

  test('a tunnel opens its statistics', async ({ authenticatedPage: page }) => {
    await openOverlayPage(page);

    const stats = page
      .locator('[data-testid="tunnels-table"]')
      .getByRole('button', { name: /^Stats / });
    if ((await stats.count()) === 0) {
      test.skip(true, 'no tunnels on this server');
    }
    await stats.first().click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Tunnel statistics');
    await expect(dialog).toContainText('Bytes sent');
  });

  test('forgetting an unknown MAC is refused or accepted without breaking the page', async ({
    authenticatedPage: page,
  }) => {
    await openOverlayPage(page);

    const form = page.locator('[data-testid="overlay-forget-mac"]');
    await form.getByLabel('MAC address').fill('02:00:00:00:e2:e2');
    await form.getByLabel('VNI').fill('16777000');
    await form.getByRole('button', { name: 'Forget MAC' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Forget', exact: true }).click();

    await expect(page.locator('[data-testid="macs-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="macs-list-error"]')).toHaveCount(0);
  });
});
