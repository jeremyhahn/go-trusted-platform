import { test, expect } from './fixtures';

/**
 * Tenant dashboard (/admin/tenant) against the real server.
 *
 * Ported from web/e2e/tenant.spec.ts (#2037). The seeded admin logs in through
 * WebAuthn and the page reads the seeded tenant from the harness server.
 * Member-session, no-tenant, injected 500/network-failure, delayed-response
 * loading and forged-member-count cases had no server behaviour behind them
 * and are listed as gaps in the PR body.
 */

test.describe('Tenant Dashboard (real server)', () => {
  test.describe('Authenticated Tenant Owner', () => {
    test('displays the tenant information the server returns', async ({ adminPage, tenant }) => {
      await adminPage.goto('/admin/tenant');

      await expect(adminPage.getByRole('heading', { name: /tenant dashboard/i })).toBeVisible();
      await expect(adminPage.getByText(/workspace id/i)).toBeVisible();
      await expect(
        adminPage.locator('[class*="infoValue"]').filter({ hasText: tenant.id }),
      ).toBeVisible();
      await expect(
        adminPage.locator('[class*="infoLabel"]').filter({ hasText: 'Members' }),
      ).toBeVisible();
    });

    test('displays the workspace name', async ({ adminPage, tenant }) => {
      await adminPage.goto('/admin/tenant');
      await expect(adminPage.getByText(tenant.name).first()).toBeVisible();
    });

    test('shows the invitation action to the owner', async ({ adminPage }) => {
      await adminPage.goto('/admin/tenant');

      await expect(adminPage.getByText(/manage invitations/i)).toBeVisible();
      await expect(adminPage.getByText(/invite new members/i)).toBeVisible();
    });

    test('navigates to the invitations page', async ({ adminPage }) => {
      await adminPage.goto('/admin/tenant');

      const invitationsLink = adminPage.getByText(/manage invitations/i);
      await expect(invitationsLink).toBeVisible({ timeout: 10000 });
      await invitationsLink.click();

      await expect(adminPage).toHaveURL(/\/admin\/invitations/);
    });

    test('navigates to the dashboard', async ({ adminPage }) => {
      await adminPage.goto('/admin/tenant');

      const dashboardLink = adminPage
        .locator(
          'a[href*="/dashboard"], button:has-text("Dashboard"), [class*="actionCard"]:has-text("Dashboard")',
        )
        .first();
      await expect(dashboardLink).toBeVisible({ timeout: 10000 });
      await dashboardLink.click();

      await expect(adminPage).toHaveURL(/\/dashboard/);
    });

    test('displays the workspace header', async ({ adminPage }) => {
      await adminPage.goto('/admin/tenant');
      await expect(adminPage.locator('header')).toContainText('Trusted Platform');
    });

    test('shows the management section with action cards', async ({ adminPage }) => {
      await adminPage.goto('/admin/tenant');

      await expect(adminPage.getByRole('heading', { name: /management/i })).toBeVisible();
      await expect(adminPage.getByText(/manage invitations/i)).toBeVisible();
      await expect(adminPage.getByText(/view members/i)).toBeVisible();
      await expect(adminPage.getByText(/dashboard/i).first()).toBeVisible();
    });

    test('logs out and clears the session cookie', async ({ adminPage }) => {
      await adminPage.goto('/admin/tenant');

      await adminPage.click('button:has-text("Logout")');

      await expect(adminPage).toHaveURL(/\/auth\/webauthn/);
      const cookies = await adminPage.context().cookies();
      expect(cookies.find((c) => c.name === 'jwt')).toBeUndefined();

      // The server no longer honours the old session.
      await adminPage.goto('/admin/tenant');
      await expect(adminPage).toHaveURL(/\/auth\/webauthn/);
    });
  });

  test.describe('Unauthenticated Access', () => {
    test('redirects to login when not authenticated', async ({ page }) => {
      await page.goto('/admin/tenant');
      await expect(page).toHaveURL(/\/auth\/webauthn|\/auth|\/login/, { timeout: 15000 });
    });
  });

  test.describe('Navigation', () => {
    test('navigates between tenant pages and back', async ({ adminPage }) => {
      await adminPage.goto('/admin/tenant');

      const invitationsLink = adminPage.getByText(/manage invitations/i);
      await expect(invitationsLink).toBeVisible({ timeout: 10000 });
      await invitationsLink.click();
      await expect(adminPage).toHaveURL(/\/admin\/invitations/);

      const backButton = adminPage
        .locator(
          'button:has-text("Back"), a:has-text("Back"), button:has-text("Dashboard"), a[href*="/admin/tenant"]',
        )
        .first();
      await expect(backButton).toBeVisible({ timeout: 5000 });
      await backButton.click();

      await expect(adminPage).toHaveURL(/\/admin\/tenant|\/dashboard/);
    });

    test('keeps the session across navigation', async ({ adminPage }) => {
      await adminPage.goto('/admin/tenant');
      await adminPage.getByText(/manage invitations/i).click();

      await expect(adminPage).toHaveURL(/\/admin\/invitations/);
      expect(/\/auth|\/login/.test(adminPage.url())).toBe(false);
    });
  });

  test.describe('Responsive Layout', () => {
    test('renders on a mobile viewport', async ({ adminPage }) => {
      await adminPage.setViewportSize({ width: 375, height: 667 });
      await adminPage.goto('/admin/tenant');

      await expect(adminPage.getByRole('heading', { name: /tenant dashboard/i })).toBeVisible();
      await expect(adminPage.getByRole('button', { name: /logout/i })).toBeVisible();
    });

    test('renders on a tablet viewport', async ({ adminPage }) => {
      await adminPage.setViewportSize({ width: 768, height: 1024 });
      await adminPage.goto('/admin/tenant');

      await expect(adminPage.getByRole('heading', { name: /tenant dashboard/i })).toBeVisible();
      await expect(adminPage.getByText(/manage invitations/i)).toBeVisible();
    });
  });
});
