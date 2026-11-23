import { test, expect } from './fixtures';

/**
 * Dashboard cases from the mocked dashboard.spec.ts that the harness's
 * real-server dashboard.spec.ts (#2034) neither ports nor lists under
 * "Not ported" (#2035). The data is the server's; no route is mocked.
 */

test.describe('Dashboard, extra cases', () => {
  test('shows the dashboard sections once the server has answered', async ({ adminPage }) => {
    await adminPage.goto('/dashboard');
    await expect(adminPage.getByText('Tenant Information')).toBeVisible();
    await expect(adminPage.getByText('Quick Actions')).toBeVisible();
    await expect(adminPage.getByText('System Health')).toBeVisible();
  });

  test('the Certificates card opens the certificates page', async ({ adminPage }) => {
    await adminPage.goto('/dashboard');
    const card = adminPage
      .locator('a')
      .filter({ has: adminPage.locator('text="Certificates"') })
      .filter({ hasText: /\d+/ })
      .first();
    await expect(card).toBeVisible();
    await expect(card).toHaveAttribute('href', /\/ca\/certificates/);
    await card.click();
    await expect(adminPage).toHaveURL(/\/ca\/certificates/);
  });
});
