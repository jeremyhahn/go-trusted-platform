import { test, expect } from './fixtures';

/**
 * Tenant isolation against the real server.
 *
 * Ported from web/e2e/tenant-isolation.spec.ts (#2037). The mocked spec forged
 * JWT cookies for owners, members and other tenants and answered the tenant
 * and invitation routes itself. Here the seeded admin logs in through the real
 * WebAuthn flow, so every value asserted comes from the harness server.
 *
 * Mocked cases with no server behaviour behind them are listed as gaps in the
 * PR body (second tenant, member/admin-without-owner sessions, missing
 * tenant_id claim).
 */

test.describe('Tenant Isolation (real server)', () => {
  test.describe('Data Isolation', () => {
    test('displays the seeded tenant returned by the server', async ({ adminPage, tenant }) => {
      await adminPage.goto('/admin/tenant');

      await expect(
        adminPage.locator('[class*="infoValue"]').filter({ hasText: tenant.id }),
      ).toBeVisible();
      await expect(adminPage.getByText(tenant.name).first()).toBeVisible();
    });

    test('invitations created for the tenant are listed after a reload', async ({ adminPage }) => {
      const email = `iso-${Date.now()}@tenant-isolation.test`;

      await adminPage.goto('/admin/invitations');
      await adminPage.fill('#email', email);
      await adminPage.selectOption('#role', 'member');
      await adminPage.click('button:has-text("Create Invitation")');
      await expect(adminPage.getByText(/invitation created successfully/i)).toBeVisible();

      // Reload so the list comes from the server, not from component state.
      await adminPage.reload();
      await expect(adminPage.getByText(email)).toBeVisible();
    });
  });

  test.describe('Claims Reflection', () => {
    test('the tenant owner sees the manage invitations option', async ({ adminPage }) => {
      await adminPage.goto('/admin/tenant');

      await expect(adminPage.getByRole('heading', { name: /tenant dashboard/i })).toBeVisible();
      await expect(adminPage.getByText(/manage invitations/i)).toBeVisible();
    });
  });

  test.describe('Cross-Tenant Protection', () => {
    test('API calls carry the session bearer token', async ({ adminPage }) => {
      const authHeaders: string[] = [];
      adminPage.on('request', (request) => {
        if (request.url().includes('/api/v1/')) {
          const auth = request.headers()['authorization'];
          if (auth) authHeaders.push(auth);
        }
      });

      await adminPage.goto('/admin/invitations');

      await expect
        .poll(() => authHeaders.some((h) => h.startsWith('Bearer ')))
        .toBe(true);
    });
  });

  test.describe('Invitation Token Isolation', () => {
    test('a copied invitation link carries the server-issued token', async ({ adminPage }) => {
      await adminPage.context().grantPermissions(['clipboard-read', 'clipboard-write']);
      const email = `link-${Date.now()}@tenant-isolation.test`;

      await adminPage.goto('/admin/invitations');
      await adminPage.fill('#email', email);
      await adminPage.selectOption('#role', 'member');
      await adminPage.click('button:has-text("Create Invitation")');
      await expect(adminPage.getByText(/invitation created successfully/i)).toBeVisible();

      await adminPage.reload();
      const row = adminPage.locator('tr, li, [class*="invitation"]').filter({ hasText: email }).first();
      await row.locator('button:has-text("Copy Link")').click();

      const clipboardText = await adminPage.evaluate(() => navigator.clipboard.readText());
      expect(clipboardText).toContain('/auth/webauthn?invitation=');
      expect(clipboardText.split('invitation=')[1]?.length ?? 0).toBeGreaterThan(0);
    });
  });

  test.describe('Session Boundary', () => {
    test('a forged expired JWT is not accepted and redirects to login', async ({ page, baseURL }) => {
      const now = Math.floor(Date.now() / 1000);
      const enc = (obj: object): string =>
        Buffer.from(JSON.stringify(obj))
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
      const forged = `${enc({ alg: 'HS256', typ: 'JWT' })}.${enc({
        sub: 'expired-user',
        tenant_id: 'expired-tenant',
        is_tenant_owner: true,
        iat: now - 7200,
        exp: now - 3600,
      })}.${enc({ forged: true })}`;

      await page.context().addCookies([
        { name: 'jwt', value: forged, url: baseURL ?? 'http://localhost', sameSite: 'Strict' },
      ]);

      await page.goto('/admin/tenant');
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });
  });
});
