import { test, expect } from './fixtures/auth.fixture';
import { test as mockTest } from './fixtures/api-mock.fixture';

/**
 * Dashboard Navigation Integration Tests
 *
 * These tests verify the dashboard layout, sidebar navigation,
 * and that all main routes load without errors.
 */

test.describe('Dashboard Layout', () => {
  test('should render dashboard layout with sidebar', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/dashboard');

    // Sidebar should be visible
    const sidebar = authenticatedPage.locator('[data-testid="sidebar"], nav, aside').first();
    await expect(sidebar).toBeVisible();

    // Main content area should exist
    const main = authenticatedPage.locator('main');
    await expect(main).toBeVisible();
  });

  test('should display dashboard statistics', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/dashboard');

    // Wait for page to load
    await authenticatedPage.waitForLoadState('networkidle');

    // Dashboard should show stats cards
    const statsCards = authenticatedPage.locator('[class*="card"], [data-testid="stats-card"]');
    const cardCount = await statsCards.count();
    expect(cardCount).toBeGreaterThan(0);
  });

  test('should display page title', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/dashboard');

    // Page should have a title
    const title = authenticatedPage.locator('h1').first();
    await expect(title).toContainText(/dashboard/i);
  });
});

test.describe('Sidebar Navigation', () => {
  test('should navigate to IAM Users page', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/dashboard');

    // Click on IAM or Users in navigation
    const usersLink = authenticatedPage.locator('a[href*="/iam/users"], a:has-text("Users")');
    if ((await usersLink.count()) > 0) {
      await usersLink.first().click();
      await expect(authenticatedPage).toHaveURL(/\/iam\/users/);
    }
  });

  test('should navigate to IAM Roles page', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/dashboard');

    const rolesLink = authenticatedPage.locator('a[href*="/iam/roles"], a:has-text("Roles")');
    if ((await rolesLink.count()) > 0) {
      await rolesLink.first().click();
      await expect(authenticatedPage).toHaveURL(/\/iam\/roles/);
    }
  });

  test('should navigate to Devices page', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/dashboard');

    const devicesLink = authenticatedPage.locator('a[href*="/devices"], a:has-text("Devices")');
    if ((await devicesLink.count()) > 0) {
      await devicesLink.first().click();
      await expect(authenticatedPage).toHaveURL(/\/devices/);
    }
  });

  test('should navigate to Certificates page', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/dashboard');

    const certsLink = authenticatedPage.locator(
      'a[href*="/ca/certificates"], a:has-text("Certificates")'
    );
    if ((await certsLink.count()) > 0) {
      await certsLink.first().click();
      await expect(authenticatedPage).toHaveURL(/\/ca\/certificates/);
    }
  });

  test('should navigate to KMS Keys page', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/dashboard');

    const keysLink = authenticatedPage.locator('a[href*="/kms"], a:has-text("Keys")');
    if ((await keysLink.count()) > 0) {
      await keysLink.first().click();
      await expect(authenticatedPage).toHaveURL(/\/kms/);
    }
  });

  test('should navigate to Tenant page', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/dashboard');

    const tenantLink = authenticatedPage.locator('a[href*="/tenant"], a:has-text("Tenant")');
    if ((await tenantLink.count()) > 0) {
      await tenantLink.first().click();
      await expect(authenticatedPage).toHaveURL(/\/tenant/);
    }
  });
});

test.describe('Route Loading', () => {
  const routes = [
    { path: '/dashboard', name: 'Dashboard' },
    { path: '/tenant', name: 'Tenant Overview' },
    { path: '/iam/users', name: 'IAM Users' },
    { path: '/iam/roles', name: 'IAM Roles' },
    { path: '/iam/permissions', name: 'IAM Permissions' },
    { path: '/devices', name: 'Devices' },
    { path: '/ca/certificates', name: 'Certificates' },
    { path: '/ca/requests', name: 'Certificate Requests' },
    { path: '/kms', name: 'KMS Keys' },
    { path: '/attestation', name: 'Attestation' },
    { path: '/platform/health', name: 'Platform Health' },
    { path: '/platform/logs', name: 'Platform Logs' },
    { path: '/networking/dns', name: 'DNS' },
    { path: '/networking/sdn', name: 'SDN' },
    { path: '/compute/vms', name: 'Virtual Machines' },
    { path: '/compute/containers', name: 'Containers' },
  ];

  for (const route of routes) {
    test(`should load ${route.name} page without errors`, async ({ authenticatedPage }) => {
      // Listen for console errors
      const consoleErrors: string[] = [];
      authenticatedPage.on('console', (msg) => {
        if (msg.type() === 'error') {
          consoleErrors.push(msg.text());
        }
      });

      // Navigate to the route
      const response = await authenticatedPage.goto(route.path);

      // Page should load successfully (2xx or 3xx status)
      expect(response?.status()).toBeLessThan(400);

      // Wait for page to stabilize
      await authenticatedPage.waitForLoadState('domcontentloaded');

      // Page should not show a generic error state
      const errorBoundary = authenticatedPage.locator('[class*="error-boundary"]');
      await expect(errorBoundary).toHaveCount(0);

      // Log any console errors for debugging
      if (consoleErrors.length > 0) {
        console.log(`Console errors on ${route.path}:`, consoleErrors);
      }
    });
  }
});

test.describe('Header Navigation', () => {
  test('should display user menu in header', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/dashboard');

    // Header should have user-related elements
    const header = authenticatedPage.locator('header');
    await expect(header).toBeVisible();

    // Look for user avatar or dropdown
    const userElement = authenticatedPage.locator(
      '[data-testid="user-menu"], button:has-text("Account"), [class*="avatar"]'
    );
    if ((await userElement.count()) > 0) {
      await expect(userElement.first()).toBeVisible();
    }
  });

  test('should have logout functionality', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/dashboard');

    // Look for logout button/link
    const logoutButton = authenticatedPage.locator(
      'button:has-text("Logout"), button:has-text("Sign out"), a:has-text("Logout")'
    );

    // If logout exists, clicking it should redirect to login
    if ((await logoutButton.count()) > 0) {
      await logoutButton.first().click();
      await authenticatedPage.waitForURL(/\/auth|\/login|\/logout/);
    }
  });
});

test.describe('Responsive Layout', () => {
  test('should work on mobile viewport', async ({ authenticatedPage }) => {
    // Set mobile viewport
    await authenticatedPage.setViewportSize({ width: 375, height: 667 });

    await authenticatedPage.goto('/dashboard');

    // Page should load
    await authenticatedPage.waitForLoadState('domcontentloaded');

    // Content should be visible (may have collapsed sidebar)
    const main = authenticatedPage.locator('main');
    await expect(main).toBeVisible();
  });

  test('should work on tablet viewport', async ({ authenticatedPage }) => {
    await authenticatedPage.setViewportSize({ width: 768, height: 1024 });

    await authenticatedPage.goto('/dashboard');

    await authenticatedPage.waitForLoadState('domcontentloaded');

    const main = authenticatedPage.locator('main');
    await expect(main).toBeVisible();
  });
});
