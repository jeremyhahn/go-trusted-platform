/**
 * NTP page against the real-server harness (#2058, ruling 972), run by
 * `make web-e2e`.
 *
 * No page.route and no api-mock: the harness's adminPage carries a
 * server-issued session, and the test reads GET /api/v1/capabilities and
 * the NTP routes from the running server. The test daemon may run with NTP
 * enabled or without it, so the spec accepts the status card or the
 * not-enabled card. The clock is never stepped: the confirm dialog is opened
 * and cancelled.
 */

import type { Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

interface Capability {
  op: string;
  kind?: string;
  enabled: boolean;
  reason?: string;
}

function isGet(path: string) {
  return (r: Response) => new URL(r.url()).pathname === path && r.request().method() === 'GET';
}

test.describe('NTP page', () => {
  test('shows the status card or the not-enabled card, with Step Clock gated', async ({
    adminPage: page,
  }) => {
    const capsResponse = page.waitForResponse(isGet('/api/v1/capabilities'));
    const statusResponse = page
      .waitForResponse(isGet('/api/v1/ntp/status'), { timeout: 15_000 })
      .catch(() => null);
    await page.goto('/networking/ntp');

    const r = await capsResponse;
    expect(r.status()).toBe(200);
    const list: Capability[] =
      unwrapPayload<{ capabilities?: Capability[] }>(await r.json()).capabilities ?? [];
    expect(list.length).toBeGreaterThan(0);

    const enabled = (op: string) => list.find((c) => c.op === op)?.enabled === true;
    const statusEnabled = enabled('GET /api/v1/ntp/status');
    const stepEnabled = enabled('POST /api/v1/ntp/step');

    const statusCard = page.locator('[data-testid="ntp-status-card"]');
    const notEnabled = page.locator('[data-testid="ntp-not-enabled"]');
    if (statusEnabled) {
      const status = await statusResponse;
      expect(status, 'GET /api/v1/ntp/status was not read').not.toBeNull();
      expect(status!.status()).toBe(200);
      await expect(statusCard).toBeVisible();
      await expect(notEnabled).toHaveCount(0);
    } else {
      await expect(notEnabled).toBeVisible();
    }

    const step = page.getByRole('button', { name: 'Step Clock' });
    await expect(step).toHaveAttribute('data-capability-op', 'POST /api/v1/ntp/step');
    await expect(step).toHaveAttribute('data-capability-enabled', String(stepEnabled));

    if (stepEnabled) {
      await step.click();
      await expect(page.getByRole('dialog')).toBeVisible();
      await page.getByRole('button', { name: 'Cancel' }).click();
      await expect(page.getByRole('dialog')).toBeHidden();
    }
  });
});
