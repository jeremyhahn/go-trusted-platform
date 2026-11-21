/**
 * NTP page against the real-server harness (#2058, ruling 972).
 *
 * No page.route and no api-mock: the page reads GET /api/v1/capabilities and
 * the NTP routes from the running server. The clock is never stepped: the
 * confirm dialog is opened and cancelled.
 */

import { test, expect } from './fixtures/auth.fixture';

test.describe('NTP page', () => {
  test('shows the status card or the not-enabled card, with Step Clock gated', async ({
    authenticatedPage: page,
  }) => {
    await page.goto('/networking/ntp');

    const statusCard = page.locator('[data-testid="ntp-status-card"]');
    const notEnabled = page.locator('[data-testid="ntp-not-enabled"]');
    await expect(statusCard.or(notEnabled).first()).toBeVisible();

    const step = page.getByRole('button', { name: 'Step Clock' });
    await expect(step).toHaveAttribute('data-capability-op', 'POST /api/v1/ntp/step');
    await expect(step).toHaveAttribute('data-capability-enabled', /^(true|false)$/);

    if ((await step.getAttribute('data-capability-enabled')) === 'true') {
      await step.click();
      await expect(page.getByRole('dialog')).toBeVisible();
      await page.getByRole('button', { name: 'Cancel' }).click();
      await expect(page.getByRole('dialog')).toBeHidden();
    }
  });
});
