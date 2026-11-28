import { test, expect } from './fixtures';

/**
 * Authentication cases from the mocked auth.spec.ts that the harness's
 * auth.spec.ts (#2034) does not cover (#2035). The form cases need no
 * server; the protected-route case signs in as the seeded admin through the
 * real WebAuthn login (`adminPage`).
 */

test.describe('Authentication form, extra cases', () => {
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

test.describe('Invitation link on the auth page, extra cases', () => {
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

test.describe('Protected routes, signed in', () => {
  test('lets the signed-in admin reach a protected route', async ({ adminPage }) => {
    await adminPage.goto('/admin/tenant');
    await expect(adminPage).toHaveURL(/\/admin\/tenant/);
    await expect(adminPage.getByRole('heading', { name: /tenant dashboard/i })).toBeVisible();
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
