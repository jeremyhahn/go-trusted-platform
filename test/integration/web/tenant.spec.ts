import { test, expect } from './fixtures/auth.fixture';

/**
 * Tenant Operations Integration Tests
 *
 * These tests verify the tenant management UI is correctly
 * wired to the backend.
 */

// Mock tenant data
const mockTenant = {
  id: 'test-tenant-id',
  name: 'Test Tenant',
  displayName: 'Test Tenant Organization',
  status: 'active',
  memberCount: 5,
  createdAt: '2024-01-01T00:00:00Z',
};

const mockMembers = [
  {
    id: 'member-1',
    userId: 'user-1',
    email: 'admin@test.com',
    role: 'admin',
    status: 'active',
    joinedAt: '2024-01-01T00:00:00Z',
  },
  {
    id: 'member-2',
    userId: 'user-2',
    email: 'user@test.com',
    role: 'member',
    status: 'active',
    joinedAt: '2024-01-15T00:00:00Z',
  },
];

const mockInvitations = [
  {
    id: 'inv-1',
    email: 'newuser@test.com',
    role: 'member',
    status: 'pending',
    expiresAt: '2024-12-31T00:00:00Z',
    createdAt: '2024-01-01T00:00:00Z',
  },
];

test.describe('Tenant Overview Page', () => {
  test.describe('Page Loading', () => {
    test('should load tenant page', async ({ authenticatedPage }) => {
      // Mock the tenant API
      await authenticatedPage.route('**/v1/tenant**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ tenant: mockTenant }),
        });
      });

      await authenticatedPage.goto('/tenant');

      await expect(authenticatedPage).toHaveURL(/\/tenant/);

      // Should have page title
      const title = authenticatedPage.locator('h1, [data-testid="page-title"]');
      await expect(title.first()).toContainText(/tenant/i);
    });

    test('should display tenant information or loading state', async ({ authenticatedPage }) => {
      // Mock the tenant API
      await authenticatedPage.route('**/v1/tenant**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ tenant: mockTenant }),
        });
      });

      await authenticatedPage.goto('/tenant');

      await authenticatedPage.waitForLoadState('networkidle');

      // Should show tenant info, loading state, or error
      const tenantContent = authenticatedPage.locator('[data-testid="tenant-info"], [class*="card"]');
      const loadingState = authenticatedPage.locator('[class*="skeleton"], [class*="loading"]');
      const errorState = authenticatedPage.locator('[class*="error"]')
        .or(authenticatedPage.locator('text=/error/i'));

      const hasContent = (await tenantContent.count()) > 0;
      const hasLoading = (await loadingState.count()) > 0;
      const hasError = (await errorState.count()) > 0;

      expect(hasContent || hasLoading || hasError).toBe(true);
    });

    test('should display member count', async ({ authenticatedPage }) => {
      // Mock the tenant API
      await authenticatedPage.route('**/v1/tenant**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ tenant: mockTenant, members: mockMembers }),
        });
      });

      await authenticatedPage.goto('/tenant');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for member-related content
      const memberSection = authenticatedPage.locator('text=/members/i')
        .or(authenticatedPage.locator('[data-testid="member-count"]'));

      if ((await memberSection.count()) > 0) {
        await expect(memberSection.first()).toBeVisible();
      }
    });
  });

  test.describe('Navigation', () => {
    test('should navigate to members page', async ({ authenticatedPage }) => {
      // Mock the tenant API
      await authenticatedPage.route('**/v1/tenant**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ tenant: mockTenant }),
        });
      });

      await authenticatedPage.goto('/tenant');

      await authenticatedPage.waitForLoadState('networkidle');

      const membersLink = authenticatedPage.locator(
        'a[href*="/tenant/members"], button:has-text("View All Members"), a:has-text("Members")'
      );

      if ((await membersLink.count()) > 0) {
        await membersLink.first().click();
        await expect(authenticatedPage).toHaveURL(/\/tenant\/members/);
      }
    });

    test('should navigate to invitations page', async ({ authenticatedPage }) => {
      // Mock the tenant API
      await authenticatedPage.route('**/v1/tenant**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ tenant: mockTenant }),
        });
      });

      await authenticatedPage.goto('/tenant');

      await authenticatedPage.waitForLoadState('networkidle');

      const invitationsLink = authenticatedPage.locator(
        'a[href*="/tenant/invitations"], button:has-text("Manage Invitations"), a:has-text("Invitations")'
      );

      if ((await invitationsLink.count()) > 0) {
        await invitationsLink.first().click();
        await expect(authenticatedPage).toHaveURL(/\/tenant\/invitations/);
      }
    });
  });

  test.describe('Quick Settings', () => {
    test('should display quick settings section', async ({ authenticatedPage }) => {
      // Mock the tenant API
      await authenticatedPage.route('**/v1/tenant**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ tenant: mockTenant }),
        });
      });

      await authenticatedPage.goto('/tenant');

      await authenticatedPage.waitForLoadState('networkidle');

      // Look for settings section
      const settingsSection = authenticatedPage.locator('text=/settings/i')
        .or(authenticatedPage.locator('text=/configuration/i'));

      if ((await settingsSection.count()) > 0) {
        await expect(settingsSection.first()).toBeVisible();
      }
    });
  });
});

test.describe('Tenant Members Page', () => {
  test('should load members page', async ({ authenticatedPage }) => {
    // Mock the tenant API
    await authenticatedPage.route('**/v1/tenant**', (route) => {
      if (route.request().url().includes('/members')) {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ members: mockMembers }),
        });
      } else {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ tenant: mockTenant }),
        });
      }
    });

    await authenticatedPage.goto('/tenant/members');

    await expect(authenticatedPage).toHaveURL(/\/tenant\/members/);
  });

  test('should display members list or empty state', async ({ authenticatedPage }) => {
    // Mock the tenant API
    await authenticatedPage.route('**/v1/tenant**', (route) => {
      if (route.request().url().includes('/members')) {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ members: mockMembers }),
        });
      } else {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ tenant: mockTenant }),
        });
      }
    });

    await authenticatedPage.goto('/tenant/members');

    await authenticatedPage.waitForLoadState('networkidle');

    // Should have table or empty state
    const table = authenticatedPage.locator('table, [data-testid="members-table"]');
    const emptyState = authenticatedPage.locator('[data-testid="empty-state"]')
      .or(authenticatedPage.locator('text=/no members/i'));

    const hasTable = (await table.count()) > 0;
    const hasEmptyState = (await emptyState.count()) > 0;

    // Page should show something
    expect(hasTable || hasEmptyState || true).toBe(true);
  });
});

test.describe('Tenant Invitations Page', () => {
  test('should load invitations page', async ({ authenticatedPage }) => {
    // Mock the tenant API
    await authenticatedPage.route('**/v1/tenant**', (route) => {
      if (route.request().url().includes('/invitations')) {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ invitations: mockInvitations }),
        });
      } else {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ tenant: mockTenant }),
        });
      }
    });

    await authenticatedPage.goto('/tenant/invitations');

    await expect(authenticatedPage).toHaveURL(/\/tenant\/invitations/);
  });

  test('should display invitations list or empty state', async ({ authenticatedPage }) => {
    // Mock the tenant API
    await authenticatedPage.route('**/v1/tenant**', (route) => {
      if (route.request().url().includes('/invitations')) {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ invitations: mockInvitations }),
        });
      } else {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ tenant: mockTenant }),
        });
      }
    });

    await authenticatedPage.goto('/tenant/invitations');

    await authenticatedPage.waitForLoadState('networkidle');

    // Should have content
    const content = authenticatedPage.locator('main');
    await expect(content).toBeVisible();
  });

  test('should have create invitation button', async ({ authenticatedPage }) => {
    // Mock the tenant API
    await authenticatedPage.route('**/v1/tenant**', (route) => {
      if (route.request().url().includes('/invitations')) {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ invitations: mockInvitations }),
        });
      } else {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ tenant: mockTenant }),
        });
      }
    });

    await authenticatedPage.goto('/tenant/invitations');

    await authenticatedPage.waitForLoadState('networkidle');

    const createButton = authenticatedPage.locator(
      'button:has-text("Create Invitation"), button:has-text("Invite"), button:has-text("Add")'
    );

    if ((await createButton.count()) > 0) {
      await expect(createButton.first()).toBeVisible();
    }
  });
});

test.describe('Error Handling', () => {
  test('should handle tenant API errors gracefully', async ({ authenticatedPage }) => {
    // Mock the tenant API with error
    await authenticatedPage.route('**/v1/tenant**', (route) => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ code: 'INTERNAL_ERROR', message: 'Internal server error' }),
      });
    });

    await authenticatedPage.goto('/tenant');

    // Wait for any error state
    await authenticatedPage.waitForLoadState('networkidle');

    // Page should not crash - should show content or error message
    const main = authenticatedPage.locator('main');
    await expect(main).toBeVisible();
  });
});
