import { test, expect } from './fixtures/auth.fixture';

/**
 * Authentication Flow Integration Tests
 *
 * These tests verify the authentication UI is correctly wired to the backend.
 * Tests cover WebAuthn registration, login, and protected route access.
 */

test.describe('Authentication Flow', () => {
  test.describe('WebAuthn Page Access', () => {
    test('should display WebAuthn authentication page at /auth/webauthn', async ({ page }) => {
      await page.goto('/auth/webauthn');

      // Page should load without errors
      await expect(page).toHaveURL(/\/auth\/webauthn/);

      // Should show authentication form
      const heading = page.locator('h2');
      await expect(heading).toBeVisible();

      // Should have username input
      const usernameInput = page.getByPlaceholder(/username/i);
      await expect(usernameInput).toBeVisible();
    });

    test('should display registration form by default', async ({ page }) => {
      await page.goto('/auth/webauthn?status=not_registered');

      await expect(page.locator('h2')).toContainText(/create account/i);
      await expect(page.getByRole('button', { name: /register/i })).toBeVisible();
    });

    test('should display login form when status=registered', async ({ page }) => {
      await page.goto('/auth/webauthn?status=registered');

      await expect(page.locator('h2')).toContainText(/login/i);
      await expect(page.getByRole('button', { name: /log in/i })).toBeVisible();
    });

    test('should toggle between registration and login forms', async ({ page }) => {
      await page.goto('/auth/webauthn?status=not_registered');

      // Should show registration form
      await expect(page.locator('h2')).toContainText(/create account/i);

      // Click to switch to login
      await page.click('text=Already have an account');
      await expect(page.locator('h2')).toContainText(/login/i);

      // Click to switch back to registration
      await page.click("text=Don't have an account");
      await expect(page.locator('h2')).toContainText(/create account/i);
    });
  });

  test.describe('Protected Route Redirection', () => {
    test('should redirect unauthenticated users from /dashboard to /auth/webauthn', async ({
      page,
    }) => {
      // Clear any existing cookies
      await page.context().clearCookies();

      // Try to access dashboard
      await page.goto('/dashboard');

      // Should redirect to login
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });

    test('should redirect unauthenticated users from /tenant to /auth/webauthn', async ({
      page,
    }) => {
      await page.context().clearCookies();
      await page.goto('/tenant');
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });

    test('should redirect unauthenticated users from /iam/users to /auth/webauthn', async ({
      page,
    }) => {
      await page.context().clearCookies();
      await page.goto('/iam/users');
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });

    test('should redirect unauthenticated users from /devices to /auth/webauthn', async ({
      page,
    }) => {
      await page.context().clearCookies();
      await page.goto('/devices');
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });

    test('should redirect unauthenticated users from /ca/certificates to /auth/webauthn', async ({
      page,
    }) => {
      await page.context().clearCookies();
      await page.goto('/ca/certificates');
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });

    test('should redirect unauthenticated users from /kms to /auth/webauthn', async ({ page }) => {
      await page.context().clearCookies();
      await page.goto('/kms');
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });
  });

  test.describe('Authenticated Access', () => {
    test('should allow authenticated users to access /dashboard', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/dashboard');

      // Should stay on dashboard (not redirected)
      await expect(authenticatedPage).toHaveURL(/\/dashboard/);

      // Dashboard content should be visible
      await expect(authenticatedPage.locator('h1, [data-testid="page-title"]')).toBeVisible();
    });

    test('should allow authenticated users to access /tenant', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/tenant');
      await expect(authenticatedPage).toHaveURL(/\/tenant/);
    });

    test('should allow authenticated users to access /iam/users', async ({ authenticatedPage }) => {
      await authenticatedPage.goto('/iam/users');
      await expect(authenticatedPage).toHaveURL(/\/iam\/users/);
    });
  });

  test.describe('Form Validation', () => {
    test('should show validation error for empty username on registration', async ({ page }) => {
      await page.goto('/auth/webauthn?status=not_registered');

      // Click register without entering username
      await page.click('button:has-text("Register")');

      // Should show validation error (login says "your username", register says "a username")
      await expect(page.getByText(/please enter (a|your) username/i)).toBeVisible();
    });

    test('should show validation error for empty username on login', async ({ page }) => {
      await page.goto('/auth/webauthn?status=registered');

      // Click login without entering username
      await page.click('button:has-text("Log In")');

      // Should show validation error (login says "your username", register says "a username")
      await expect(page.getByText(/please enter (a|your) username/i)).toBeVisible();
    });
  });

  test.describe('Invitation Flow', () => {
    test('should show invitation UI when invitation token is present', async ({ page }) => {
      await page.goto('/auth/webauthn?invitation=mock-token&tenant_name=Test%20Workspace');

      // Should show invitation-specific UI
      await expect(page.locator('h2')).toContainText(/join workspace/i);
      await expect(page.getByText(/invited to join/i)).toBeVisible();
    });
  });
});

test.describe('WebAuthn Virtual Authenticator', () => {
  test('should detect WebAuthn support in browser', async ({ page }) => {
    await page.goto('/auth/webauthn');

    // Check that the browser supports WebAuthn
    const hasWebAuthn = await page.evaluate(() => {
      return typeof window.PublicKeyCredential !== 'undefined';
    });

    expect(hasWebAuthn).toBe(true);
  });

  test('should detect platform authenticator availability', async ({ page }) => {
    await page.goto('/auth/webauthn');

    const hasPlatformAuthenticator = await page.evaluate(async () => {
      if (typeof window.PublicKeyCredential === 'undefined') {
        return false;
      }
      try {
        return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      } catch {
        return false;
      }
    });

    // Log the result for debugging
    console.log('Platform authenticator available:', hasPlatformAuthenticator);
    // Don't assert - availability depends on environment
  });
});
