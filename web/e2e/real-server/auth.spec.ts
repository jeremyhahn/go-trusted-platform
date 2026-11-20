import { test, expect, type BrowserContext, type CDPSession, type Page } from '@playwright/test';

/**
 * web/e2e/auth.spec.ts ported to the real server (#2034, epic #1665).
 *
 * The console and its API are the platformd global-setup.ts started; nothing
 * is mocked. Registration and login are real WebAuthn ceremonies: Chromium's
 * virtual authenticator (CDP) answers navigator.credentials, the server
 * verifies the attestation/assertion and sets the session cookie itself.
 */

let seq = 0;

/** A username no earlier test (or earlier run on a kept data dir) took. */
function uniqueEmail(tag: string): string {
  seq += 1;
  return `e2e-${tag}-${Date.now().toString(36)}-${seq}@example.com`;
}

/** Adds a resident-key, user-verifying platform authenticator to the page. */
async function addAuthenticator(page: Page): Promise<{ cdp: CDPSession; id: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, id: authenticatorId };
}

async function jwtCookie(context: BrowserContext) {
  return (await context.cookies()).find((c) => c.name === 'jwt');
}

/** Registers username through the form; resolves on /dashboard. */
async function register(page: Page, username: string): Promise<void> {
  await page.goto('/auth/webauthn?status=not_registered');
  await page.getByPlaceholder('Enter your email').fill(username);
  await page.getByRole('button', { name: /register/i }).click();
  await expect(page).toHaveURL(/\/dashboard/, { timeout: 30000 });
}

/** Logs out through the account menu; resolves on the login page. */
async function logout(page: Page): Promise<void> {
  await page.getByTestId('header-account-menu').click();
  await page.getByRole('menuitem', { name: /log out/i }).click();
  await expect(page).toHaveURL(/\/auth\/webauthn/, { timeout: 30000 });
}

test.describe('Authentication forms', () => {
  test('should display registration form by default', async ({ page }) => {
    await page.goto('/auth/webauthn?status=not_registered');

    await expect(page.locator('h2')).toContainText('Create Account');
    await expect(page.getByPlaceholder('Enter your email')).toBeVisible();
    await expect(page.getByRole('button', { name: /register/i })).toBeVisible();
  });

  test('should display login form, with no username field, when status=registered', async ({ page }) => {
    await page.goto('/auth/webauthn?status=registered');

    await expect(page.locator('h2')).toContainText('Login');
    await expect(page.getByRole('button', { name: /log in/i })).toBeVisible();
    // Login is usernameless (discoverable credentials).
    await expect(page.getByPlaceholder('Enter your email')).toHaveCount(0);
  });

  test('should toggle between registration and login forms', async ({ page }) => {
    await page.goto('/auth/webauthn?status=not_registered');
    await expect(page.locator('h2')).toContainText('Create Account');

    await page.click('text=Already have an account? Log In');
    await expect(page.locator('h2')).toContainText('Login');

    await page.click("text=Don't have an account? Register");
    await expect(page.locator('h2')).toContainText('Create Account');
  });

  test('should show invitation UI when invitation token is present', async ({ page }) => {
    await page.goto('/auth/webauthn?invitation=some-token&tenant_name=Test%20Workspace');

    await expect(page.locator('h2')).toContainText('Join Workspace');
    await expect(page.getByText(/You've been invited to join Test Workspace/i)).toBeVisible();
  });

  test('should validate username input', async ({ page }) => {
    await page.goto('/auth/webauthn?status=not_registered');
    await page.click('button:has-text("Register")');

    await expect(page.getByText(/please enter your email address/i)).toBeVisible();
  });
});

test.describe('Protected routes', () => {
  for (const route of ['/admin/tenant', '/admin/invitations', '/dashboard']) {
    test(`should redirect ${route} to login without a session`, async ({ page }) => {
      await page.goto(route);
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });
  }
});

test.describe('Registration and login against the server', () => {
  test('registration creates the account, sets the session and opens the dashboard', async ({ page }) => {
    await addAuthenticator(page);
    await register(page, uniqueEmail('reg'));

    const jwt = await jwtCookie(page.context());
    expect(jwt, 'the server sets the jwt cookie').toBeTruthy();
    expect(jwt!.value.split('.')).toHaveLength(3);
  });

  test('an authenticated user is sent from the login page to the dashboard', async ({ page }) => {
    await addAuthenticator(page);
    await register(page, uniqueEmail('redir'));

    await page.goto('/auth/webauthn');
    await expect(page).toHaveURL(/\/dashboard/);
  });

  test('log out clears the session; protected routes redirect again', async ({ page }) => {
    await addAuthenticator(page);
    await register(page, uniqueEmail('logout'));

    await logout(page);
    expect(await jwtCookie(page.context())).toBeUndefined();

    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('a registered user logs in again with their passkey', async ({ page }) => {
    await addAuthenticator(page);
    await register(page, uniqueEmail('login'));
    await logout(page);

    await page.goto('/auth/webauthn?status=registered');
    await page.getByRole('button', { name: /log in/i }).click();
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 30000 });
    expect(await jwtCookie(page.context())).toBeTruthy();
  });

  test('registering an existing account is refused with an error', async ({ page, browser }) => {
    const username = uniqueEmail('dup');
    await addAuthenticator(page);
    await register(page, username);

    // A second browser context, so no session: the same username again.
    const other = await browser.newContext({ ignoreHTTPSErrors: true });
    try {
      const second = await other.newPage();
      await addAuthenticator(second);
      await second.goto('/auth/webauthn?status=not_registered');
      await second.getByPlaceholder('Enter your email').fill(username);
      await second.getByRole('button', { name: /register/i }).click();

      await expect(second.locator('[class*="error"]').first()).toBeVisible({ timeout: 30000 });
      await expect(second).toHaveURL(/\/auth\/webauthn/);
      expect(await jwtCookie(other)).toBeUndefined();
    } finally {
      await other.close();
    }
  });

  test('login with no credential for this site shows an error', async ({ page }) => {
    // An authenticator holding no credential: the ceremony cannot complete.
    await addAuthenticator(page);
    await page.goto('/auth/webauthn?status=registered');
    await page.getByRole('button', { name: /log in/i }).click();

    await expect(page.locator('[class*="error"]').first()).toBeVisible({ timeout: 30000 });
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });
});
