import { test, expect } from './fixtures/auth.fixture';

/**
 * WebAuthn E2E Integration Tests
 *
 * Tests exercise the full WebAuthn registration and login flows against
 * the running backend using Chrome's virtual authenticator via CDP.
 *
 * Environment variables:
 *   FRONTEND_URL  - e.g. https://server.example.com:8443
 *   BACKEND_URL   - e.g. https://server.example.com:8443
 *   NO_WEB_SERVER - set to 1 when frontend is served by the backend
 */

function uniqueUsername(prefix = 'e2e'): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

/** Navigate to WebAuthn page and switch to registration mode. */
async function goToRegistration(page: import('@playwright/test').Page) {
  await page.goto('/auth/webauthn', { waitUntil: 'networkidle' });

  // The page may default to login mode. If we see "Don't have an account? Register",
  // click it to switch to registration mode.
  const registerLink = page.getByText(/don.*have an account.*register/i);
  if (await registerLink.isVisible({ timeout: 3000 }).catch(() => false)) {
    await registerLink.click();
    // Wait for the registration form to appear
    await expect(page.getByRole('button', { name: /register|create account/i })).toBeVisible();
  }
}

/** Navigate to WebAuthn page in login mode. */
async function goToLogin(page: import('@playwright/test').Page) {
  await page.goto('/auth/webauthn', { waitUntil: 'networkidle' });

  // If registration form is showing, switch to login
  const loginLink = page.getByText(/already have an account.*log in/i);
  if (await loginLink.isVisible({ timeout: 3000 }).catch(() => false)) {
    await loginLink.click();
    await expect(page.getByRole('button', { name: /log in/i })).toBeVisible();
  }
}

/** Assert auth succeeded — JWT cookie present and no longer on auth page. */
async function assertAuthSuccess(page: import('@playwright/test').Page) {
  // Wait for navigation away from auth page or for dashboard content
  await page.waitForFunction(() => {
    return !window.location.pathname.includes('/auth/webauthn') ||
      document.body.innerText.includes('Dashboard') ||
      document.body.innerText.includes('Protected') ||
      document.body.innerText.includes('Log Out') ||
      document.body.innerText.includes('Overview');
  }, { timeout: 15_000 });

  // JWT cookie must be present
  const cookies = await page.context().cookies();
  const jwtCookie = cookies.find((c) => c.name === 'jwt');
  expect(jwtCookie).toBeDefined();
  expect(jwtCookie!.value.length).toBeGreaterThan(0);
}

test.describe('WebAuthn E2E — Real Backend', () => {
  test.describe.configure({ mode: 'serial' });

  test.describe('Registration', () => {
    test('full registration flow sets JWT cookie', async ({
      page,
      setupVirtualAuthenticator,
      cleanupVirtualAuthenticator,
    }) => {
      const username = uniqueUsername('reg');

      await goToRegistration(page);

      const { cdpSession, authenticatorId } = await setupVirtualAuthenticator(page);

      try {
        await page.getByPlaceholder(/enter your username/i).fill(username);

        const registrationFinishPromise = page.waitForResponse(
          (resp) =>
            resp.url().includes('/api/v1/webauthn/registration/finish') &&
            resp.status() === 200
        );

        // Click Register or Create Account button
        await page.getByRole('button', { name: /register|create account/i }).click();

        await registrationFinishPromise;

        await assertAuthSuccess(page);
      } finally {
        await cleanupVirtualAuthenticator(cdpSession, authenticatorId);
      }
    });
  });

  test.describe('Login', () => {
    test('full login flow sets JWT cookie', async ({
      page,
      setupVirtualAuthenticator,
      cleanupVirtualAuthenticator,
    }) => {
      const username = uniqueUsername('login');

      // --- Registration phase (setup) ---
      await goToRegistration(page);

      const { cdpSession, authenticatorId } = await setupVirtualAuthenticator(page);

      try {
        await page.getByPlaceholder(/enter your username/i).fill(username);

        const regFinish = page.waitForResponse(
          (resp) =>
            resp.url().includes('/api/v1/webauthn/registration/finish') &&
            resp.status() === 200
        );
        await page.getByRole('button', { name: /register|create account/i }).click();
        await regFinish;
        await assertAuthSuccess(page);

        // Clear session
        await page.context().clearCookies();

        // --- Login phase ---
        await goToLogin(page);

        await page.getByPlaceholder(/enter your username/i).fill(username);

        const loginFinishPromise = page.waitForResponse(
          (resp) =>
            resp.url().includes('/api/v1/webauthn/login/finish') &&
            resp.status() === 200
        );

        await page.getByRole('button', { name: /log in/i }).click();

        await loginFinishPromise;

        await assertAuthSuccess(page);
      } finally {
        await cleanupVirtualAuthenticator(cdpSession, authenticatorId);
      }
    });
  });

  test.describe('Error cases', () => {
    test('registration with duplicate username shows error', async ({
      page,
      setupVirtualAuthenticator,
      cleanupVirtualAuthenticator,
    }) => {
      const username = uniqueUsername('dup');

      await goToRegistration(page);

      const { cdpSession, authenticatorId } = await setupVirtualAuthenticator(page);

      try {
        // First registration — must succeed
        await page.getByPlaceholder(/enter your username/i).fill(username);

        const firstFinish = page.waitForResponse(
          (resp) =>
            resp.url().includes('/api/v1/webauthn/registration/finish') &&
            resp.status() === 200
        );
        await page.getByRole('button', { name: /register|create account/i }).click();
        await firstFinish;
        await assertAuthSuccess(page);

        // Clear cookies and go back to registration
        await page.context().clearCookies();
        await goToRegistration(page);

        await page.getByPlaceholder(/enter your username/i).fill(username);

        // Second attempt — should fail
        const secondBegin = page.waitForResponse(
          (resp) => resp.url().includes('/api/v1/webauthn/registration/begin')
        );
        await page.getByRole('button', { name: /register|create account/i }).click();
        await secondBegin;

        // Error message should appear
        await expect(
          page.getByText(/already exists|error|failed|try again|log in instead/i)
        ).toBeVisible({ timeout: 10_000 });
      } finally {
        await cleanupVirtualAuthenticator(cdpSession, authenticatorId);
      }
    });

    test('login with non-existent username shows error', async ({ page }) => {
      const username = uniqueUsername('ghost');

      await goToLogin(page);

      await page.getByPlaceholder(/enter your username/i).fill(username);

      const loginBeginResponse = page.waitForResponse(
        (resp) => resp.url().includes('/api/v1/webauthn/login/begin')
      );

      await page.getByRole('button', { name: /log in/i }).click();

      await loginBeginResponse;

      await expect(
        page.getByText(/not found|error|failed|try again|does not exist|no passkey/i)
      ).toBeVisible({ timeout: 10_000 });
    });
  });

  test.describe('Post-auth content', () => {
    test('after registration, authenticated content is visible', async ({
      page,
      setupVirtualAuthenticator,
      cleanupVirtualAuthenticator,
    }) => {
      const username = uniqueUsername('content');

      await goToRegistration(page);

      const { cdpSession, authenticatorId } = await setupVirtualAuthenticator(page);

      try {
        await page.getByPlaceholder(/enter your username/i).fill(username);

        const regFinish = page.waitForResponse(
          (resp) =>
            resp.url().includes('/api/v1/webauthn/registration/finish') &&
            resp.status() === 200
        );
        await page.getByRole('button', { name: /register|create account/i }).click();
        await regFinish;
        await assertAuthSuccess(page);

        // After auth, the page should not show the login form
        await expect(page.getByRole('button', { name: /log in/i })).not.toBeVisible({ timeout: 5000 });
      } finally {
        await cleanupVirtualAuthenticator(cdpSession, authenticatorId);
      }
    });
  });

  test.describe('Sign out', () => {
    // The header's Log out was a `// TODO: Implement logout logic` stub that
    // only navigated, and the sidebar's Log out had no handler at all. Both
    // left the `jwt` cookie in place, so the operator was moved off the
    // dashboard while still signed in and could walk straight back in.
    // Landing on the login page is therefore NOT evidence of a logout — the
    // cookie and a protected route are. Both controls are covered because
    // fixing only the one that was reported leaves the other still broken.
    const signOutControls = [
      {
        name: 'header profile menu',
        open: async (page: import('@playwright/test').Page) => {
          await page.getByTestId('header-account-menu').click();
        },
      },
      {
        name: 'sidebar account menu',
        open: async (page: import('@playwright/test').Page) => {
          await page.getByTestId('sidebar-account-menu').click();
        },
      },
    ];

    for (const control of signOutControls) {
      test(`${control.name} Log out clears the session, not just the view`, async ({
        page,
        setupVirtualAuthenticator,
        cleanupVirtualAuthenticator,
      }) => {
        const username = uniqueUsername('logout');

        await goToRegistration(page);
        const { cdpSession, authenticatorId } = await setupVirtualAuthenticator(page);

        try {
          await page.getByPlaceholder(/enter your username/i).fill(username);
          const regFinish = page.waitForResponse(
            (resp) =>
              resp.url().includes('/api/v1/webauthn/registration/finish') &&
              resp.status() === 200
          );
          await page.getByRole('button', { name: /register|create account/i }).click();
          await regFinish;
          await assertAuthSuccess(page);

          await page.goto('/dashboard', { waitUntil: 'networkidle' });
          await control.open(page);
          await page.getByRole('menuitem', { name: /log out/i }).click();

          // The session cookie must be gone.
          await expect
            .poll(
              async () =>
                (await page.context().cookies()).some(
                  (c) => c.name === 'jwt' && c.value !== ''
                ),
              { timeout: 10_000 }
            )
            .toBe(false);

          // And the protected route must no longer be reachable.
          await page.goto('/dashboard', { waitUntil: 'networkidle' });
          await expect
            .poll(() => page.url(), { timeout: 10_000 })
            .not.toContain('/dashboard');
        } finally {
          await cleanupVirtualAuthenticator(cdpSession, authenticatorId);
        }
      });
    }
  });
});
