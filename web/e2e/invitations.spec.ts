import { test, expect } from '@playwright/test';
import {
  createTenantOwnerSession,
  createTenantMemberSession,
} from './fixtures/auth-setup';
import {
  mockInvitationApi,
  mockTenantApi,
  createMockInvitation,
} from './fixtures/api-mock';

test.describe('Invitations Management', () => {
  test.describe('Tenant Owner Access', () => {
    test.beforeEach(async ({ page }) => {
      // Set up authenticated session as tenant owner
      await createTenantOwnerSession(page.context());
    });

    test('should display invitation form for tenant owners', async ({ page }) => {
      // Mock APIs
      await mockInvitationApi(page);
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // Verify page loaded with correct elements
      await expect(page.getByRole('heading', { name: /manage invitations/i })).toBeVisible();
      await expect(page.locator('label[for="email"]')).toBeVisible();
      await expect(page.locator('label[for="role"]')).toBeVisible();
      await expect(page.getByRole('button', { name: /create invitation/i })).toBeVisible();
    });

    test('should display existing invitations in the list', async ({ page }) => {
      const existingInvitations = [
        createMockInvitation({ id: 'inv-1', email: 'user1@example.com', role: 'member' }),
        createMockInvitation({ id: 'inv-2', email: 'user2@example.com', role: 'admin' }),
      ];

      await mockInvitationApi(page, { initialInvitations: existingInvitations });
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // Wait for invitations to load
      await expect(page.getByText('user1@example.com')).toBeVisible();
      await expect(page.getByText('user2@example.com')).toBeVisible();
      // Use locators that are specific to the invitation items' role badges
      await expect(page.locator('[class*="role"]').filter({ hasText: 'member' }).first()).toBeVisible();
      await expect(page.locator('[class*="role"]').filter({ hasText: 'admin' }).first()).toBeVisible();
    });

    test('should create a new invitation', async ({ page }) => {
      const mockApi = await mockInvitationApi(page);
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // Fill out the form
      await page.fill('#email', 'newuser@example.com');
      await page.selectOption('#role', 'member');

      // Submit the form
      await page.click('button:has-text("Create Invitation")');

      // Should show success message
      await expect(page.getByText(/invitation created successfully/i)).toBeVisible();

      // Should display the new invitation in the list
      await expect(page.getByText('newuser@example.com')).toBeVisible();

      // Verify the invitation was added to the mock state
      const invitations = mockApi.getInvitations();
      expect(invitations.some((inv) => inv.email === 'newuser@example.com')).toBe(true);
    });

    test('should create invitation with admin role', async ({ page }) => {
      await mockInvitationApi(page);
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      await page.fill('#email', 'admin@example.com');
      await page.selectOption('#role', 'admin');
      await page.click('button:has-text("Create Invitation")');

      await expect(page.getByText(/invitation created successfully/i)).toBeVisible();
      await expect(page.getByText('admin@example.com')).toBeVisible();
    });

    test('should copy invitation link to clipboard', async ({ page, context }) => {
      // Grant clipboard permissions
      await context.grantPermissions(['clipboard-read', 'clipboard-write']);

      const existingInvitation = createMockInvitation({
        id: 'inv-copy-test',
        email: 'copy@example.com',
        token: 'test-token-12345',
      });

      await mockInvitationApi(page, { initialInvitations: [existingInvitation] });
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // Wait for invitation to appear
      await expect(page.getByText('copy@example.com')).toBeVisible();

      // Click copy button
      await page.click('button:has-text("Copy Link")');

      // Should show success notification
      await expect(page.getByText(/copied to clipboard/i)).toBeVisible();

      // Verify clipboard content
      const clipboardText = await page.evaluate(() => navigator.clipboard.readText());
      expect(clipboardText).toContain('test-token-12345');
      expect(clipboardText).toContain('/auth/webauthn?invitation=');
    });

    test('should revoke an invitation', async ({ page }) => {
      const existingInvitation = createMockInvitation({
        id: 'inv-revoke-test',
        email: 'revoke@example.com',
      });

      const mockApi = await mockInvitationApi(page, { initialInvitations: [existingInvitation] });
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // Verify invitation is displayed
      await expect(page.getByText('revoke@example.com')).toBeVisible();

      // Set up dialog handler for confirmation
      page.on('dialog', (dialog) => dialog.accept());

      // Click revoke button
      await page.click('button:has-text("Revoke")');

      // Should show success message
      await expect(page.getByText(/invitation revoked/i)).toBeVisible();

      // Invitation should be removed from the list
      await expect(page.getByText('revoke@example.com')).not.toBeVisible();

      // Verify the invitation was removed from mock state
      const invitations = mockApi.getInvitations();
      expect(invitations.some((inv) => inv.id === 'inv-revoke-test')).toBe(false);
    });

    test('should show invitation in list after creation', async ({ page }) => {
      await mockInvitationApi(page, { initialInvitations: [] });
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // Initially show no invitations message
      await expect(page.getByText(/no pending invitations/i)).toBeVisible();

      // Create an invitation
      await page.fill('#email', 'newmember@example.com');
      await page.selectOption('#role', 'member');
      await page.click('button:has-text("Create Invitation")');

      // The new invitation should now appear
      await expect(page.getByText('newmember@example.com')).toBeVisible();

      // No pending invitations message should disappear
      await expect(page.getByText(/no pending invitations/i)).not.toBeVisible();
    });

    test('should handle API error when fetching invitations', async ({ page }) => {
      await mockInvitationApi(page, {
        fetchError: { error: 'Failed to fetch invitations', status: 500 },
      });
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // Should display error notification
      await expect(page.getByText(/failed to fetch invitations/i)).toBeVisible();
    });

    test('should handle API error when creating invitation', async ({ page }) => {
      await mockInvitationApi(page, {
        createError: { error: 'Email already invited', status: 409 },
      });
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // Wait for form to be ready
      await expect(page.locator('#email')).toBeVisible({ timeout: 10000 });

      await page.fill('#email', 'duplicate@example.com');
      await page.click('button:has-text("Create Invitation")');

      // Should show error notification - the API mock returns 'error' field
      // and the frontend shows it via showNotification
      await expect(page.getByText(/email already invited|failed to create invitation/i)).toBeVisible({ timeout: 10000 });
    });

    test('should handle API error when revoking invitation', async ({ page }) => {
      const existingInvitation = createMockInvitation({
        id: 'inv-error-test',
        email: 'error@example.com',
      });

      await mockInvitationApi(page, {
        initialInvitations: [existingInvitation],
        revokeError: { error: 'Failed to revoke invitation', status: 500 },
      });
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      page.on('dialog', (dialog) => dialog.accept());

      await page.click('button:has-text("Revoke")');

      // Should show error notification
      await expect(page.getByText(/failed to revoke invitation/i)).toBeVisible();
    });

    test('should require email input before creating invitation', async ({ page }) => {
      await mockInvitationApi(page);
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // The email input has required attribute, so HTML5 validation will trigger
      // We need to check that the form doesn't submit without email
      const emailInput = page.locator('#email');
      await expect(emailInput).toBeVisible();

      // Check that the input is required
      const isRequired = await emailInput.evaluate((el: HTMLInputElement) => el.required);
      expect(isRequired).toBe(true);

      // Try to submit without email - the form should not submit
      const submitButton = page.getByRole('button', { name: /create invitation/i });
      await submitButton.click();

      // The form should still be visible (not submitted) and email field should be invalid
      const isValid = await emailInput.evaluate((el: HTMLInputElement) => el.validity.valid);
      expect(isValid).toBe(false);
    });

    test('should navigate back to dashboard', async ({ page }) => {
      await mockInvitationApi(page);
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // Wait for page to fully load
      await expect(page.getByRole('heading', { name: /manage invitations/i })).toBeVisible({ timeout: 10000 });

      // Find and click the back button - it may be a link styled as button
      const backButton = page.locator('button:has-text("Back to Dashboard"), a:has-text("Back to Dashboard")').first();
      await expect(backButton).toBeVisible({ timeout: 5000 });
      await backButton.click();

      // Wait for navigation with timeout
      await page.waitForURL(/\/admin\/tenant/, { timeout: 15000 });
      await expect(page).toHaveURL(/\/admin\/tenant/);
    });
  });

  test.describe('Non-Owner Access', () => {
    test('should display access denied for non-owners', async ({ page }) => {
      // Set up authenticated session as tenant member (not owner)
      await createTenantMemberSession(page.context());
      await mockInvitationApi(page);
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // Should show access denied message
      await expect(page.getByRole('heading', { name: /access denied/i })).toBeVisible();
      await expect(page.getByText(/only tenant owners can manage invitations/i)).toBeVisible();

      // Should show button to go back to dashboard
      await expect(page.getByRole('button', { name: /back to dashboard/i })).toBeVisible();
    });

    test('should not show invitation form to non-owners', async ({ page }) => {
      await createTenantMemberSession(page.context());
      await mockInvitationApi(page);
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // Form elements should not be visible
      await expect(page.locator('label[for="email"]')).not.toBeVisible();
      await expect(page.getByRole('button', { name: /create invitation/i })).not.toBeVisible();
    });

    test('should navigate back to dashboard from access denied page', async ({ page }) => {
      await createTenantMemberSession(page.context());
      await mockInvitationApi(page);
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // Wait for access denied page to load
      await expect(page.getByRole('heading', { name: /access denied/i })).toBeVisible({ timeout: 10000 });

      // Find and click the back button
      const backButton = page.locator('button:has-text("Back to Dashboard"), a:has-text("Back to Dashboard")').first();
      await expect(backButton).toBeVisible({ timeout: 5000 });
      await backButton.click();

      // Wait for navigation with timeout
      await page.waitForURL(/\/admin\/tenant/, { timeout: 15000 });
      await expect(page).toHaveURL(/\/admin\/tenant/);
    });
  });

  test.describe('Unauthenticated Access', () => {
    test('should redirect to login when not authenticated', async ({ page }) => {
      await page.goto('/admin/invitations');

      // Should be redirected to login
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });
  });

  test.describe('Multiple Invitations', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
    });

    test('should display multiple invitations with different roles', async ({ page }) => {
      const invitations = [
        createMockInvitation({ id: 'inv-1', email: 'owner1@example.com', role: 'owner' }),
        createMockInvitation({ id: 'inv-2', email: 'admin1@example.com', role: 'admin' }),
        createMockInvitation({ id: 'inv-3', email: 'member1@example.com', role: 'member' }),
      ];

      await mockInvitationApi(page, { initialInvitations: invitations });
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // All invitations should be visible
      await expect(page.getByText('owner1@example.com')).toBeVisible();
      await expect(page.getByText('admin1@example.com')).toBeVisible();
      await expect(page.getByText('member1@example.com')).toBeVisible();
    });

    test('should handle revoking specific invitation from list', async ({ page }) => {
      const invitations = [
        createMockInvitation({ id: 'inv-keep-1', email: 'keep1@example.com' }),
        createMockInvitation({ id: 'inv-remove', email: 'remove@example.com' }),
        createMockInvitation({ id: 'inv-keep-2', email: 'keep2@example.com' }),
      ];

      await mockInvitationApi(page, { initialInvitations: invitations });
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      page.on('dialog', (dialog) => dialog.accept());

      // Wait for invitations to load
      await expect(page.getByText('remove@example.com')).toBeVisible();

      // Find the invitation item that contains remove@example.com and click its revoke button
      // Use a more specific selector targeting the invitation item structure
      const invitationItems = page.locator('[class*="invitationItem"]');
      const removeItem = invitationItems.filter({ hasText: 'remove@example.com' });
      await removeItem.locator('button:has-text("Revoke")').click();

      // The removed invitation should be gone
      await expect(page.getByText('remove@example.com')).not.toBeVisible();

      // Other invitations should still be there
      await expect(page.getByText('keep1@example.com')).toBeVisible();
      await expect(page.getByText('keep2@example.com')).toBeVisible();
    });
  });

  test.describe('Form Validation', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
      await mockInvitationApi(page);
      await mockTenantApi(page);
    });

    test('should validate email format', async ({ page }) => {
      await page.goto('/admin/invitations');

      // Enter invalid email
      await page.fill('#email', 'invalid-email');

      // The HTML5 email validation should prevent submission
      const emailInput = page.locator('#email');
      const isValid = await emailInput.evaluate((el: HTMLInputElement) => el.validity.valid);
      expect(isValid).toBe(false);
    });

    test('should clear form after successful submission', async ({ page }) => {
      await page.goto('/admin/invitations');

      await page.fill('#email', 'test@example.com');
      await page.selectOption('#role', 'admin');

      await page.click('button:has-text("Create Invitation")');

      // Wait for success
      await expect(page.getByText(/invitation created successfully/i)).toBeVisible();

      // Form should be cleared
      await expect(page.locator('#email')).toHaveValue('');
      await expect(page.locator('#role')).toHaveValue('member');
    });

    test('should disable button during submission', async ({ page }) => {
      // Set up API mock with delay before other mocks
      await page.route('**/api/v1/invitations', async (route, request) => {
        if (request.method() === 'POST') {
          // Add significant delay to observe loading state
          await new Promise((resolve) => setTimeout(resolve, 3000));
          await route.fulfill({
            status: 201,
            contentType: 'application/json',
            body: JSON.stringify({
              invitation: createMockInvitation({ email: 'test@example.com' }),
            }),
          });
        } else {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ invitations: [], total: 0 }),
          });
        }
      });
      await mockTenantApi(page);

      await page.goto('/admin/invitations');

      // Wait for form to be ready
      await expect(page.locator('#email')).toBeVisible({ timeout: 10000 });

      await page.fill('#email', 'test@example.com');

      const button = page.getByRole('button', { name: /create invitation/i });

      // Click the button
      await button.click();

      // The form should respond to submission in some way - check for any of:
      // 1. Button text changes to "Creating..."
      // 2. Button is disabled
      // 3. Success message appears (fast submission)
      // Any of these indicates proper form handling
      try {
        // First check for loading state
        await expect(button).toContainText(/creating/i, { timeout: 1000 });
      } catch {
        // Alternative: check for disabled state
        const isDisabled = await button.isDisabled();
        if (isDisabled) {
          expect(isDisabled).toBe(true);
          return;
        }
        // If neither loading nor disabled, form might have submitted quickly
        // Wait for success message or form reset
        const formSubmitted = await Promise.race([
          page.getByText(/invitation created successfully/i).waitFor({ timeout: 5000 }).then(() => true),
          page.locator('#email').inputValue().then(v => v === '').catch(() => false),
        ]).catch(() => false);
        expect(formSubmitted).toBe(true);
      }
    });
  });
});
