import { test, expect } from './fixtures';

/**
 * Authentication flow against the real-server harness (#2035).
 *
 * The form cases need no server; the protected-route and session cases run
 * against the harness server, signed out (`page`) or signed in as the seeded
 * admin through the real WebAuthn login (`adminPage`). Registration and
 * login ceremonies that need a second authenticator are listed as gaps in the
 * PR body: the harness seeds one admin credential only.
 */

test.describe('Authentication form', () => {
  test('shows the registration form by default', async ({ page }) => {
    await page.goto('/auth/webauthn?status=not_registered');

    await expect(page.locator('h2')).toContainText('Create Account');
    await expect(page.getByPlaceholder('Enter your email')).toBeVisible();
    await expect(page.getByRole('button', { name: /register/i })).toBeVisible();
  });

  test('shows the login form, with no username field, when status=registered', async ({ page }) => {
    await page.goto('/auth/webauthn?status=registered');

    await expect(page.locator('h2')).toContainText('Login');
    await expect(page.getByRole('button', { name: /log in/i })).toBeVisible();
    // Login is usernameless: the authenticator picks the credential.
    await expect(page.getByPlaceholder('Enter your email')).toHaveCount(0);
  });

  test('toggles between registration and login forms', async ({ page }) => {
    await page.goto('/auth/webauthn?status=not_registered');
    await expect(page.locator('h2')).toContainText('Create Account');

    await page.click('text=Already have an account? Log In');
    await expect(page.locator('h2')).toContainText('Login');

    await page.click("text=Don't have an account? Register");
    await expect(page.locator('h2')).toContainText('Create Account');
  });

  test('requires an email to register', async ({ page }) => {
    await page.goto('/auth/webauthn?status=not_registered');
    await page.click('button:has-text("Register")');
    await expect(page.getByText(/please enter your email address/i)).toBeVisible();
  });

  test('does not require a username to log in', async ({ page }) => {
    await page.goto('/auth/webauthn?status=registered');
    await page.click('button:has-text("Log In")');
    await expect(page.getByText(/please enter your username/i)).not.toBeVisible();
  });

  test('keeps the form usable after a validation error', async ({ page }) => {
    await page.goto('/auth/webauthn?status=not_registered');
    await page.click('button:has-text("Register")');
    await expect(page.getByText(/please enter your email address/i)).toBeVisible();

    await page.fill('input[placeholder="Enter your email"]', 't');
    await expect(page.getByRole('button', { name: /register/i })).toBeEnabled();
  });
});

test.describe('Invitation link on the auth page', () => {
  test('shows the invitation UI with the tenant name', async ({ page }) => {
    await page.goto('/auth/webauthn?invitation=e2e-token&tenant_name=Acme%20Corp');

    await expect(page.locator('h2')).toContainText('Join Workspace');
    await expect(page.getByText(/You've been invited to join Acme Corp/i)).toBeVisible();
    await expect(page.getByPlaceholder('Enter your email')).toBeVisible();
    await expect(page.getByRole('button', { name: /register/i })).toBeVisible();
  });

  test('shows a generic invitation message without a tenant name', async ({ page }) => {
    await page.goto('/auth/webauthn?invitation=e2e-token');

    await expect(page.locator('h2')).toContainText('Join Workspace');
    await expect(page.getByText(/You've been invited to join a workspace/i)).toBeVisible();
  });

  test('allows toggling to login with an invitation', async ({ page }) => {
    await page.goto('/auth/webauthn?invitation=e2e-token&tenant_name=Test%20Team');
    await expect(page.locator('h2')).toContainText('Join Workspace');

    await page.click('text=Already have an account? Log In');
    await expect(page.locator('h2')).toContainText('Login');
  });
});

test.describe('Protected routes, real server', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
  });

  for (const path of ['/admin/tenant', '/admin/invitations', '/dashboard']) {
    test(`redirects ${path} to login when signed out`, async ({ page }) => {
      await page.goto(path);
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });
  }

  test('lets the signed-in admin reach a protected route', async ({ adminPage }) => {
    await adminPage.goto('/admin/tenant');
    await expect(adminPage).toHaveURL(/\/admin\/tenant/);
    await expect(adminPage.getByRole('heading', { name: /tenant dashboard/i })).toBeVisible();
  });
});

test.describe('Session management, real server', () => {
  test('the real WebAuthn login leaves a session cookie', async ({ adminPage }) => {
    const cookies = await adminPage.context().cookies();
    const jwt = cookies.find((c) => c.name === 'jwt');
    expect(jwt?.value ?? '').toContain('.');
  });

  test('redirects the signed-in admin from login to the dashboard', async ({ adminPage }) => {
    await adminPage.goto('/auth/webauthn');
    await expect(adminPage).toHaveURL(/\/dashboard/);
  });

  test('logout clears the session, and a protected page then redirects to login', async ({ adminPage }) => {
    await adminPage.goto('/admin/tenant');
    await adminPage.click('button:has-text("Logout")');
    await expect(adminPage).toHaveURL(/\/auth\/webauthn/);

    const cookies = await adminPage.context().cookies();
    expect(cookies.find((c) => c.name === 'jwt')).toBeUndefined();

    await adminPage.goto('/admin/tenant');
    await expect(adminPage).toHaveURL(/\/auth\/webauthn/);
  });
});

test.describe('Accessibility', () => {
  test('the email input is visible and enabled', async ({ page }) => {
    await page.goto('/auth/webauthn?status=not_registered');
    const input = page.getByPlaceholder('Enter your email');
    await expect(input).toBeVisible();
    await expect(input).toBeEnabled();
  });

  test('supports keyboard navigation', async ({ page }) => {
    await page.goto('/auth/webauthn?status=not_registered');
    const input = page.getByPlaceholder('Enter your email');
    await input.click();
    expect(await input.evaluate((el) => document.activeElement === el)).toBe(true);

    await page.keyboard.type('testuser');
    await expect(input).toHaveValue('testuser');
    await page.keyboard.press('Tab');
    const register = page.getByRole('button', { name: /register/i });
    await expect(register).toBeVisible();
    await expect(register).toBeEnabled();
  });

  test('has visible focus indicators', async ({ page }) => {
    await page.goto('/auth/webauthn?status=not_registered');
    const input = page.getByPlaceholder('Enter your email');
    await input.click();
    await input.focus();
    await expect(input).toBeFocused();
  });
});
