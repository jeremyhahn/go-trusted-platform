import type { Locator, Page } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Admin workspace page (/admin/tenant) against the real platformd (#2067,
 * epic #1665).
 *
 * No page.route mocks: the page reads the session's tenant through
 * GET /api/v1/tenants/{id}, and each assertion compares what the page shows
 * with what the server answered the page itself.
 */

interface WireTenant {
  id?: string;
  name?: string;
  displayName?: string;
  state?: string;
}

/** The value cell that follows an info label on the workspace card. */
function infoValue(page: Page, label: string): Locator {
  return page.getByText(label, { exact: true }).locator('xpath=following-sibling::div[1]');
}

test.describe('Admin workspace (real server)', () => {
  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/admin/tenant');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('shows the workspace the server answers', async ({ adminPage, tenant }) => {
    const tenantPath = `/api/v1/tenants/${tenant.id}`;
    const answered = adminPage.waitForResponse(
      (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === tenantPath,
    );
    await adminPage.goto('/admin/tenant');
    const res = await answered;
    expect(res.ok(), `${res.url()} answered ${res.status()}`).toBeTruthy();
    const { tenant: wire } = unwrapPayload<{ tenant: WireTenant }>(await res.json());

    await expect(adminPage.getByRole('heading', { name: 'Tenant Dashboard' })).toBeVisible();
    await expect(infoValue(adminPage, 'Workspace ID')).toHaveText(tenant.id);

    const name = wire.displayName || wire.name;
    expect(name, 'the server names the tenant').toBeTruthy();
    await expect(infoValue(adminPage, 'Workspace Name')).toHaveText(name as string);

    if (wire.state) {
      await expect(infoValue(adminPage, 'State')).toHaveText(wire.state);
    }
  });

  test('Dashboard opens the control panel', async ({ adminPage }) => {
    await adminPage.goto('/admin/tenant');
    await expect(adminPage.getByRole('heading', { name: 'Tenant Dashboard' })).toBeVisible();
    await adminPage.getByText('Dashboard', { exact: true }).click();
    await expect(adminPage).toHaveURL(/\/dashboard/);
  });
});
