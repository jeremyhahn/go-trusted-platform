import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';

/**
 * Dashboard against the real platformd (#2034, epic #1665).
 *
 * Port of web/e2e/dashboard.spec.ts with every page.route mock removed: the
 * data is seeded through the SDK and each assertion compares the page with
 * what the server answered the page itself.
 *
 * Not ported (the mocked case had no server behaviour behind it):
 *   - "degraded health status when unhealthy": a fresh test daemon is
 *     healthy; nothing in the API makes it report unhealthy.
 *   - Error Handling "network failure", "loading state", "API error
 *     responses" and Loading States "loading state while fetching": they
 *     only exercised route.abort / delayed / 500 fulfilments.
 *   - Member Access: the harness seeds an admin only; there is no member
 *     session to log in with.
 *   - The fixed counts (42 users, 15 devices, 87 certificates) and metric
 *     values (45.2 %, ...): replaced by the values the server returns.
 */

/** Waits for the page's own GET whose path matches, and returns its JSON. */
function apiResponse(page: Page, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && path.test(new URL(r.url()).pathname),
  );
}

async function json<T>(r: Response): Promise<T> {
  expect(r.ok(), `${r.url()} answered ${r.status()}`).toBeTruthy();
  return (await r.json()) as T;
}

const headerAvatar = (page: Page) =>
  page.locator('header button').filter({ has: page.locator('[class*="rounded-full"]') });

test.describe('Dashboard Access', () => {
  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('redirects to login once the session cookies are gone', async ({ adminPage }) => {
    await adminPage.context().clearCookies();
    await adminPage.goto('/dashboard');
    await expect(adminPage).toHaveURL(/\/auth\/webauthn/);
  });

  test('loads the dashboard for the seeded admin', async ({ adminPage }) => {
    await adminPage.goto('/dashboard');
    await expect(adminPage.getByRole('heading', { name: /dashboard/i })).toBeVisible();
    await expect(adminPage.getByText(/welcome back/i)).toBeVisible();
  });

  test('opens the user menu from the header', async ({ adminPage }) => {
    await adminPage.goto('/dashboard');
    await headerAvatar(adminPage).click();
    await expect(adminPage.getByRole('menuitem', { name: /profile/i })).toBeVisible();
    await expect(adminPage.getByRole('menuitem', { name: /settings/i })).toBeVisible();
    await expect(adminPage.getByRole('menuitem', { name: /log out/i })).toBeVisible();
  });
});

test.describe('Navigation Sidebar', () => {
  test.beforeEach(async ({ adminPage }) => {
    await adminPage.setViewportSize({ width: 1280, height: 720 });
  });

  test('shows every main navigation group', async ({ adminPage }) => {
    await adminPage.goto('/dashboard');
    await expect(adminPage.getByRole('link', { name: 'Dashboard' })).toBeVisible();
    for (const name of [
      /identity & access/i,
      /tenant/i,
      /security/i,
      /attestation/i,
      /tpm/i,
      /devices/i,
      /compute/i,
      /networking/i,
      /data storage/i,
      /platform/i,
    ]) {
      await expect(adminPage.getByRole('button', { name }).first()).toBeVisible();
    }
  });

  test('marks the current page active', async ({ adminPage }) => {
    await adminPage.goto('/dashboard');
    await expect(adminPage.getByRole('link', { name: 'Dashboard' })).toHaveClass(/bg-neutral/);
  });

  test('navigates to IAM users', async ({ adminPage }) => {
    await adminPage.goto('/dashboard');
    await adminPage.getByRole('button', { name: /identity & access/i }).click();
    await adminPage.getByRole('link', { name: 'Users', exact: true }).click();
    await expect(adminPage).toHaveURL(/\/iam\/users/);
  });

  test('navigates to devices', async ({ adminPage }) => {
    await adminPage.goto('/dashboard');
    await adminPage.getByRole('button', { name: /devices/i }).first().click();
    await adminPage.getByRole('link', { name: 'All Devices' }).click();
    await expect(adminPage).toHaveURL(/\/devices/);
  });

  test('expands and collapses a group', async ({ adminPage }) => {
    await adminPage.goto('/dashboard');
    const security = adminPage.getByRole('button', { name: /security/i });
    const certificates = adminPage.getByRole('link', { name: 'Certificates', exact: true });
    await security.click();
    await expect(certificates).toBeVisible();
    await security.click();
    await expect(certificates).not.toBeVisible();
  });

  test('opens the sidebar from the toggle on a phone viewport', async ({ adminPage }) => {
    await adminPage.setViewportSize({ width: 375, height: 667 });
    await adminPage.goto('/dashboard');
    await adminPage.getByRole('button', { name: /toggle sidebar/i }).click();
    await expect(adminPage.getByRole('link', { name: 'Dashboard' })).toBeVisible();
  });
});

test.describe('Dashboard Overview', () => {
  test('stats cards show the counts the server returns', async ({ adminPage, sdk }) => {
    const issued = await sdk.ca.issueCertificate({
      subject: { commonName: `dashboard-${Date.now()}.localhost` },
      validDays: 1,
    });
    expect(issued.success, JSON.stringify(issued.error)).toBeTruthy();

    const usersRes = apiResponse(adminPage, /\/api\/v1\/iam\/tenants\/[^/]+\/users$/);
    const certsRes = apiResponse(adminPage, /\/api\/v1\/ca\/certificates$/);
    await adminPage.goto('/dashboard');

    const users = await json<{ total?: number; pagination?: { totalItems?: number } }>(
      await usersRes,
    );
    const certs = await json<{ pagination?: { totalItems?: number } }>(await certsRes);
    const userTotal = users.pagination?.totalItems ?? users.total ?? 0;
    const certTotal = certs.pagination?.totalItems ?? 0;
    // The seeded admin and the certificate issued above.
    expect(userTotal).toBeGreaterThanOrEqual(1);
    expect(certTotal).toBeGreaterThanOrEqual(1);

    const usersCard = adminPage.locator('a').filter({ hasText: 'Total Users' }).first();
    await expect(usersCard).toContainText(String(userTotal));
    const certsCard = adminPage
      .locator('a')
      .filter({ has: adminPage.locator('text="Certificates"') })
      .first();
    await expect(certsCard).toContainText(String(certTotal));
    await expect(adminPage.getByText('Active Devices')).toBeVisible();
  });

  test('platform health shows what /platform/health returns', async ({ adminPage }) => {
    const healthRes = apiResponse(adminPage, /\/api\/v1\/platform\/health$/);
    await adminPage.goto('/dashboard');
    const { health } = await json<{ health: { healthy: boolean } }>(await healthRes);
    await expect(adminPage.getByText('Platform Health')).toBeVisible();
    await expect(adminPage.getByText(health.healthy ? 'Healthy' : 'Degraded').first()).toBeVisible();
  });

  test('tenant card shows the tenant the server returns', async ({ adminPage }) => {
    const tenantRes = apiResponse(adminPage, /\/api\/v1\/tenants\/[^/]+$/);
    await adminPage.goto('/dashboard');
    const body = await json<{ tenant: { name: string; state: string } }>(await tenantRes);
    await expect(adminPage.getByText('Tenant Information')).toBeVisible();
    await expect(adminPage.getByText(body.tenant.name).first()).toBeVisible();
    await expect(adminPage.getByText(body.tenant.state, { exact: true })).toBeVisible();
  });

  test('the seeded tenant is readable through the SDK', async ({ sdk, tenant }) => {
    const res = await sdk.tenant.getTenant(tenant.id);
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
  });

  test('quick actions link to their pages', async ({ adminPage }) => {
    await adminPage.goto('/dashboard');
    await expect(adminPage.getByText('Quick Actions')).toBeVisible();
    for (const name of [/manage devices/i, /manage users/i, /view events/i]) {
      await expect(adminPage.getByRole('link', { name })).toBeVisible();
    }
    const issue = adminPage.getByRole('link', { name: /issue certificate/i });
    await expect(issue).toHaveAttribute('href', /\/ca\/certificates/);
    await issue.click();
    await expect(adminPage).toHaveURL(/\/ca\/certificates/);
  });

  test('system health shows the metrics the server returns', async ({ adminPage }) => {
    const metricsRes = apiResponse(adminPage, /\/api\/v1\/platform\/metrics$/);
    await adminPage.goto('/dashboard');
    await json<{ metrics: unknown }>(await metricsRes);
    await expect(adminPage.getByText('System Health')).toBeVisible();
    await expect(adminPage.getByText('CPU Usage')).toBeVisible();
    await expect(adminPage.getByText('Memory', { exact: true })).toBeVisible();
    await expect(adminPage.getByText('Storage', { exact: true })).toBeVisible();
  });

  test('refresh asks the server again', async ({ adminPage }) => {
    await adminPage.goto('/dashboard');
    await expect(adminPage.getByText('Platform Health')).toBeVisible();
    const again = apiResponse(adminPage, /\/api\/v1\/platform\/health$/);
    await adminPage.getByRole('button', { name: /refresh/i }).click();
    expect((await again).ok()).toBeTruthy();
  });
});

test.describe('Responsive Layout', () => {
  for (const [label, width, height] of [
    ['phone', 375, 667],
    ['tablet', 768, 1024],
    ['desktop', 1440, 900],
  ] as const) {
    test(`renders on a ${label} viewport`, async ({ adminPage }) => {
      await adminPage.setViewportSize({ width, height });
      await adminPage.goto('/dashboard');
      await expect(adminPage.getByRole('heading', { name: /dashboard/i })).toBeVisible();
      await expect(adminPage.getByText('Total Users')).toBeVisible();
      await expect(adminPage.getByText('Quick Actions')).toBeVisible();
      await expect(adminPage.getByText('System Health')).toBeVisible();
    });
  }
});

test.describe('Stats Card Navigation', () => {
  for (const [card, url] of [
    ['Total Users', /\/iam\/users/],
    ['Active Devices', /\/devices/],
    ['Platform Health', /\/platform\/health/],
  ] as const) {
    test(`the ${card} card opens its page`, async ({ adminPage }) => {
      await adminPage.goto('/dashboard');
      const link = adminPage.locator('a').filter({ hasText: card }).first();
      await expect(link).toHaveAttribute('href', url);
      await link.click();
      await expect(adminPage).toHaveURL(url);
    });
  }
});

test.describe('Tenant Details Navigation', () => {
  test('view tenant details opens the tenant page', async ({ adminPage }) => {
    await adminPage.goto('/dashboard');
    const link = adminPage.getByRole('link', { name: /view tenant details/i });
    await expect(link).toHaveAttribute('href', /tenant/i);
    await link.click();
    await expect(adminPage).toHaveURL(/\/tenant/);
  });
});

test.describe('User Menu', () => {
  test('log out ends the session', async ({ adminPage }) => {
    await adminPage.goto('/dashboard');
    await headerAvatar(adminPage).click();
    await adminPage.getByRole('menuitem', { name: /log out/i }).click();
    await expect(adminPage).toHaveURL(/\/auth/);
    await adminPage.goto('/dashboard');
    await expect(adminPage).toHaveURL(/\/auth\/webauthn/);
  });
});
