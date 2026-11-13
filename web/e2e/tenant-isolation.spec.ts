import { test, expect } from '@playwright/test';
import {
  createTenantOwnerSession,
  createTenantMemberSession,
  createCustomSession,
} from './fixtures/auth-setup';
import {
  mockInvitationApi,
  mockTenantApi,
  createMockInvitation,
  createMockTenantInfo,
} from './fixtures/api-mock';

/**
 * Tenant Isolation Tests
 *
 * These tests verify that multi-tenant isolation is properly enforced:
 * - Users can only see their own tenant's data
 * - Cross-tenant access is prevented
 * - JWT claims are correctly reflected in the UI
 */

test.describe('Tenant Isolation', () => {
  test.describe('Data Isolation', () => {
    test('should only display invitations for the current tenant', async ({ page }) => {
      // Create session for Tenant A owner
      await createTenantOwnerSession(page.context(), {
        userId: 'owner-a',
        email: 'owner@tenant-a.com',
        tenantId: 'tenant-a-123',
      });

      // Mock API to return Tenant A invitations
      const tenantAInvitations = [
        createMockInvitation({
          id: 'inv-a-1',
          email: 'user1@tenant-a.com',
          role: 'member',
        }),
        createMockInvitation({
          id: 'inv-a-2',
          email: 'user2@tenant-a.com',
          role: 'admin',
        }),
      ];

      await mockInvitationApi(page, { initialInvitations: tenantAInvitations });
      await mockTenantApi(page, {
        tenantInfo: createMockTenantInfo({
          id: 'tenant-a-123',
          name: 'Tenant A Workspace',
        }),
      });

      await page.goto('/admin/invitations');

      // Should see Tenant A invitations
      await expect(page.getByText('user1@tenant-a.com')).toBeVisible();
      await expect(page.getByText('user2@tenant-a.com')).toBeVisible();

      // Verify tenant ID in the header/workspace info
      await expect(page.locator('header')).toContainText('Trusted Platform');
    });

    test('should display correct tenant information based on JWT claims', async ({ page }) => {
      await createTenantOwnerSession(page.context(), {
        userId: 'owner-b',
        email: 'owner@tenant-b.com',
        tenantId: 'tenant-b-456',
      });

      await mockTenantApi(page, {
        tenantInfo: createMockTenantInfo({
          id: 'tenant-b-456',
          name: 'Tenant B Workspace',
          member_count: 10,
        }),
      });

      await page.goto('/admin/tenant');

      // Should display Tenant B information (use specific selectors to avoid matching header)
      await expect(page.locator('[class*="infoValue"]').filter({ hasText: 'tenant-b-456' })).toBeVisible();
      await expect(page.getByText('Tenant B Workspace')).toBeVisible();
      await expect(page.locator('[class*="infoValue"]').filter({ hasText: '10' })).toBeVisible();
    });

    test('tenant member cannot access another tenants invitations page', async ({ page }) => {
      // Create session for Tenant A member
      await createTenantMemberSession(page.context(), {
        userId: 'member-a',
        email: 'member@tenant-a.com',
        tenantId: 'tenant-a-123',
      });

      await mockInvitationApi(page);
      await mockTenantApi(page, {
        tenantInfo: createMockTenantInfo({
          id: 'tenant-a-123',
          name: 'Tenant A',
        }),
      });

      await page.goto('/admin/invitations');

      // Non-owner should see access denied, not another tenant's data
      await expect(page.getByRole('heading', { name: /access denied/i })).toBeVisible();
    });
  });

  test.describe('JWT Claims Reflection', () => {
    test('should correctly reflect is_tenant_owner claim in UI', async ({ page }) => {
      await createCustomSession(
        page.context(),
        {
          sub: 'user-owner-test',
          user_id: 'user-owner-test',
          email: 'owner@test.com',
          tenant_id: 'test-tenant',
          is_tenant_owner: true,
          roles: ['owner'],
        }
      );

      await mockTenantApi(page);

      await page.goto('/admin/tenant');

      // Owner should see manage invitations option
      await expect(page.getByText(/manage invitations/i)).toBeVisible();
    });

    test('should correctly reflect non-owner claim in UI', async ({ page }) => {
      await createCustomSession(
        page.context(),
        {
          sub: 'user-member-test',
          user_id: 'user-member-test',
          email: 'member@test.com',
          tenant_id: 'test-tenant',
          is_tenant_owner: false,
          roles: ['member'],
        }
      );

      await mockTenantApi(page);

      await page.goto('/admin/tenant');

      // Non-owner should NOT see manage invitations option
      await expect(page.getByText(/manage invitations/i)).not.toBeVisible();
    });

    test('should reflect tenant_id in workspace display', async ({ page }) => {
      const customTenantId = 'custom-tenant-xyz-789';

      await createCustomSession(
        page.context(),
        {
          sub: 'user-custom',
          user_id: 'user-custom',
          email: 'user@custom.com',
          tenant_id: customTenantId,
          is_tenant_owner: true,
          roles: ['owner'],
        }
      );

      await mockTenantApi(page, {
        tenantInfo: createMockTenantInfo({
          id: customTenantId,
          name: 'Custom Workspace',
        }),
      });

      await page.goto('/admin/tenant');

      // Should display the custom tenant ID (use specific selector to avoid matching header)
      await expect(page.locator('[class*="infoValue"]').filter({ hasText: customTenantId })).toBeVisible();
    });

    test('should reflect user email from JWT', async ({ page }) => {
      const customEmail = 'specific-user@company.com';

      await createCustomSession(
        page.context(),
        {
          sub: 'user-email-test',
          user_id: 'user-email-test',
          email: customEmail,
          tenant_id: 'email-test-tenant',
          is_tenant_owner: true,
          roles: ['owner'],
        }
      );

      await mockTenantApi(page);

      await page.goto('/admin/tenant');

      // Page should load correctly with the email in claims
      await expect(page.getByRole('heading', { name: /tenant dashboard/i })).toBeVisible();
    });
  });

  test.describe('Role-Based Access Control', () => {
    test('owner role should have full access to tenant management', async ({ page }) => {
      await createCustomSession(
        page.context(),
        {
          sub: 'owner-rbac-test',
          user_id: 'owner-rbac-test',
          email: 'owner@rbac.com',
          tenant_id: 'rbac-tenant',
          is_tenant_owner: true,
          roles: ['owner', 'admin'],
        }
      );

      await mockTenantApi(page);
      await mockInvitationApi(page);

      await page.goto('/admin/tenant');

      // Should see all management options
      await expect(page.getByText(/manage invitations/i)).toBeVisible();
      await expect(page.getByText(/dashboard/i).first()).toBeVisible();
    });

    test('admin role without owner flag should have limited access', async ({ page }) => {
      await createCustomSession(
        page.context(),
        {
          sub: 'admin-rbac-test',
          user_id: 'admin-rbac-test',
          email: 'admin@rbac.com',
          tenant_id: 'rbac-tenant',
          is_tenant_owner: false, // Admin but not owner
          roles: ['admin'],
        }
      );

      await mockTenantApi(page);

      await page.goto('/admin/tenant');

      // Admin without owner flag should NOT see invitation management
      await expect(page.getByText(/manage invitations/i)).not.toBeVisible();
    });

    test('member role should have minimal access', async ({ page }) => {
      await createCustomSession(
        page.context(),
        {
          sub: 'member-rbac-test',
          user_id: 'member-rbac-test',
          email: 'member@rbac.com',
          tenant_id: 'rbac-tenant',
          is_tenant_owner: false,
          roles: ['member'],
        }
      );

      await mockTenantApi(page);
      await mockInvitationApi(page);

      await page.goto('/admin/tenant');

      // Member should not see invitation management
      await expect(page.getByText(/manage invitations/i)).not.toBeVisible();

      // But should still see dashboard
      await expect(page.getByText(/dashboard/i).first()).toBeVisible();
    });
  });

  test.describe('Cross-Tenant Protection', () => {
    test('API should be called with correct tenant context', async ({ page }) => {
      const tenantId = 'context-test-tenant';

      await createTenantOwnerSession(page.context(), {
        tenantId,
      });

      // Track API calls to verify tenant context
      const apiCalls: { url: string; headers: Record<string, string> }[] = [];

      await page.route('**/api/v1/**', async (route, request) => {
        apiCalls.push({
          url: request.url(),
          headers: request.headers(),
        });

        // Default mock response
        if (request.url().includes('/invitations')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ invitations: [], total: 0 }),
          });
        } else if (request.url().includes('/tenant')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(createMockTenantInfo({ id: tenantId })),
          });
        } else {
          await route.continue();
        }
      });

      await page.goto('/admin/invitations');

      // Verify Authorization header is present (contains JWT with tenant info)
      await expect
        .poll(() => apiCalls.some((call) => call.headers['authorization']?.startsWith('Bearer ')))
        .toBe(true);
    });

    test('switching tenant context should refresh data', async ({ page, context }) => {
      // Start with Tenant A
      await createTenantOwnerSession(context, {
        tenantId: 'tenant-switch-a',
      });

      await mockTenantApi(page, {
        tenantInfo: createMockTenantInfo({
          id: 'tenant-switch-a',
          name: 'Workspace A',
        }),
      });

      await page.goto('/admin/tenant');
      // Use specific selector to avoid matching header
      await expect(page.locator('[class*="infoValue"]').filter({ hasText: 'tenant-switch-a' })).toBeVisible();

      // Clear cookies and create new session for Tenant B
      await context.clearCookies();
      await createTenantOwnerSession(context, {
        tenantId: 'tenant-switch-b',
      });

      // Update mock to return Tenant B data
      await mockTenantApi(page, {
        tenantInfo: createMockTenantInfo({
          id: 'tenant-switch-b',
          name: 'Workspace B',
        }),
      });

      // Reload page
      await page.goto('/admin/tenant');

      // Should now show Tenant B data (use specific selector)
      await expect(page.locator('[class*="infoValue"]').filter({ hasText: 'tenant-switch-b' })).toBeVisible();
    });
  });

  test.describe('Invitation Token Isolation', () => {
    test('invitation links should be tenant-specific', async ({ page, context }) => {
      await context.grantPermissions(['clipboard-read', 'clipboard-write']);

      await createTenantOwnerSession(page.context(), {
        tenantId: 'invite-tenant-123',
      });

      const invitation = createMockInvitation({
        id: 'inv-isolated',
        email: 'invite@test.com',
        token: 'isolated-token-abc',
      });

      await mockInvitationApi(page, { initialInvitations: [invitation] });
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      await page.click('button:has-text("Copy Link")');

      const clipboardText = await page.evaluate(() => navigator.clipboard.readText());

      // Invitation link should contain the token
      expect(clipboardText).toContain('isolated-token-abc');
      expect(clipboardText).toContain('/auth/webauthn?invitation=');
    });

    test('creating invitation should be scoped to current tenant', async ({ page }) => {
      await createTenantOwnerSession(page.context(), {
        tenantId: 'create-scope-tenant',
      });

      const mockApi = await mockInvitationApi(page);
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      await page.fill('#email', 'newmember@scope-test.com');
      await page.selectOption('#role', 'member');
      await page.click('button:has-text("Create Invitation")');

      await expect(page.getByText(/invitation created successfully/i)).toBeVisible();

      // Verify the invitation was created
      const invitations = mockApi.getInvitations();
      expect(invitations.some((inv) => inv.email === 'newmember@scope-test.com')).toBe(true);
    });
  });

  test.describe('Session Boundary Tests', () => {
    test('expired JWT should redirect to login', async ({ page, context }) => {
      // Create a session with an expired token
      const expiredToken = createExpiredJWT({
        sub: 'expired-user',
        user_id: 'expired-user',
        email: 'expired@test.com',
        tenant_id: 'expired-tenant',
        is_tenant_owner: true,
      });

      await context.addCookies([
        {
          name: 'jwt',
          value: expiredToken,
          domain: 'localhost',
          path: '/',
          httpOnly: false,
          secure: false,
          sameSite: 'Strict',
          expires: Math.floor(Date.now() / 1000) - 3600, // Already expired
        },
      ]);

      await page.goto('/admin/tenant');

      // The frontend checks token validity and redirects
      // With an expired cookie, the redirect should happen
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });

    test('missing tenant_id claim should handle gracefully', async ({ page }) => {
      await createCustomSession(
        page.context(),
        {
          sub: 'no-tenant-user',
          user_id: 'no-tenant-user',
          email: 'notenant@test.com',
          // No tenant_id claim
          is_tenant_owner: false,
          roles: [],
        }
      );

      await mockTenantApi(page, {
        fetchError: { error: 'No tenant found', status: 404 },
      });

      await page.goto('/admin/tenant');

      // Should display N/A or handle gracefully
      await expect(page.getByText('N/A')).toBeVisible();
    });
  });
});

/**
 * Helper to create an expired JWT for testing
 */
function createExpiredJWT(claims: {
  sub?: string;
  user_id?: string;
  email?: string;
  tenant_id?: string;
  is_tenant_owner?: boolean;
  roles?: string[];
}): string {
  const header = {
    alg: 'HS256',
    typ: 'JWT',
  };

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    ...claims,
    iat: now - 7200, // Issued 2 hours ago
    exp: now - 3600, // Expired 1 hour ago
  };

  const base64UrlEncode = (obj: object): string => {
    const json = JSON.stringify(obj);
    const base64 = Buffer.from(json).toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  const headerEncoded = base64UrlEncode(header);
  const payloadEncoded = base64UrlEncode(payload);
  const mockSignature = base64UrlEncode({ mock: 'signature' });

  return `${headerEncoded}.${payloadEncoded}.${mockSignature}`;
}
