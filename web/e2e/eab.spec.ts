import { test, expect, type Page } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { createMockEABCredential, mockEABApi, mockTenantApi } from './fixtures/api-mock';

/**
 * EAB credential pages (#1667): every EAB REST operation is reachable from
 * /ca/eab or /ca/eab/[id]. The API is mocked through mockEABApi.
 */

const seed = () => [
  createMockEABCredential({ id: 1, keyId: 'kid-active', status: 'EAB_CREDENTIAL_STATUS_ACTIVE' }),
  createMockEABCredential({ id: 2, keyId: 'kid-expired', status: 'EAB_CREDENTIAL_STATUS_EXPIRED' }),
];

/**
 * Open a detail page the way the platform's static server does: it serves the
 * exported __placeholder__ HTML, and the client resolves the real id from the
 * pathname.
 */
async function openPlaceholderDetail(page: Page, id: number) {
  await page.goto('/ca/eab/__placeholder__/');
  await page.waitForLoadState('networkidle');
  await page.evaluate((credId) => window.history.pushState(null, '', `/ca/eab/${credId}/`), id);
}

test.describe('CA EAB credentials - list page', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
    await mockTenantApi(page);
  });

  test('lists credentials (ListCredentials)', async ({ page }) => {
    const api = await mockEABApi(page, seed());
    await page.goto('/ca/eab');

    await expect(page.getByRole('heading', { name: 'EAB Credentials' })).toBeVisible();
    await expect(page.getByTestId('eab-row-1')).toContainText('kid-active');
    await expect(page.getByTestId('eab-row-2')).toContainText('EXPIRED');
    expect(api.calls.some((c) => c.method === 'GET' && c.path === '')).toBe(true);
  });

  test('creates a credential (CreateCredential)', async ({ page }) => {
    const api = await mockEABApi(page, seed());
    await page.goto('/ca/eab');

    await page.getByLabel('Profile ID').fill('7');
    await page.getByLabel('Tenant ID').fill('tenant-new');
    await page.getByLabel('Expires in (seconds)').fill('3600');
    await page.getByRole('button', { name: 'Create' }).click();

    await expect(page.getByTestId('eab-created')).toContainText('hmac-secret-value');
    await expect(page.getByTestId('eab-row-3')).toContainText('tenant-new');
    const create = api.calls.find((c) => c.method === 'POST' && c.path === '');
    expect(create?.body).toEqual({ profileId: 7, tenantId: 'tenant-new', expiresInSeconds: 3600 });
  });

  test('revokes a credential (RevokeCredential)', async ({ page }) => {
    const api = await mockEABApi(page, seed());
    await page.goto('/ca/eab');

    await page.getByTestId('eab-row-1').getByRole('button', { name: 'Revoke' }).click();

    await expect(page.getByTestId('eab-message')).toHaveText('Credential 1 revoked');
    await expect(page.getByTestId('eab-row-1')).toContainText('REVOKED');
    expect(api.calls.some((c) => c.method === 'POST' && c.path === '/1/revoke')).toBe(true);
  });

  test('deletes a credential (DeleteCredential)', async ({ page }) => {
    const api = await mockEABApi(page, seed());
    await page.goto('/ca/eab');

    page.once('dialog', (dialog) => void dialog.accept());
    await page.getByTestId('eab-row-1').getByRole('button', { name: 'Delete' }).click();

    await expect(page.getByTestId('eab-message')).toHaveText('Credential 1 deleted');
    await expect(page.getByTestId('eab-row-1')).toHaveCount(0);
    expect(api.calls.some((c) => c.method === 'DELETE' && c.path === '/1')).toBe(true);
  });

  test('validates a credential (ValidateCredential)', async ({ page }) => {
    const api = await mockEABApi(page, seed());
    await page.goto('/ca/eab');

    const form = page.locator('form', { has: page.getByRole('button', { name: 'Validate' }) });
    await form.getByLabel('Key ID').fill('kid-active');
    await form.getByLabel('HMAC Key').fill('good-hmac');
    await form.getByRole('button', { name: 'Validate' }).click();
    await expect(page.getByTestId('eab-validation')).toHaveText('Valid');

    await form.getByLabel('HMAC Key').fill('bad-hmac');
    await form.getByRole('button', { name: 'Validate' }).click();
    await expect(page.getByTestId('eab-validation')).toHaveText('Invalid');

    const validate = api.calls.filter((c) => c.method === 'POST' && c.path === '/validate');
    expect(validate[0]?.body).toEqual({ keyId: 'kid-active', hmacKey: 'good-hmac' });
  });

  test('cleans up expired credentials (CleanupExpiredCredentials)', async ({ page }) => {
    const api = await mockEABApi(page, seed());
    await page.goto('/ca/eab');
    await expect(page.getByTestId('eab-row-2')).toBeVisible();

    await page.getByRole('button', { name: 'Clean Up Expired' }).click();

    await expect(page.getByTestId('eab-message')).toHaveText('Deleted 1 expired credentials');
    await expect(page.getByTestId('eab-row-2')).toHaveCount(0);
    expect(api.calls.some((c) => c.method === 'POST' && c.path === '/cleanup')).toBe(true);
  });

  test('looks up a credential by key ID (GetCredentialByKeyID)', async ({ page }) => {
    const api = await mockEABApi(page, seed());
    await page.goto('/ca/eab');

    const form = page.locator('form', { has: page.getByRole('button', { name: 'Look Up' }) });
    await form.getByLabel('Key ID').fill('kid-active');
    await form.getByRole('button', { name: 'Look Up' }).click();

    await expect(page.getByTestId('eab-lookup-result')).toContainText('Credential 1');
    expect(api.calls.some((c) => c.method === 'GET' && c.path === '/key/kid-active')).toBe(true);

    await form.getByLabel('Key ID').fill('kid-missing');
    await form.getByRole('button', { name: 'Look Up' }).click();
    await expect(page.getByRole('alert')).toBeVisible();
  });
});

test.describe('CA EAB credentials - detail page', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
    await mockTenantApi(page);
  });

  test('shows a credential (GetCredential)', async ({ page }) => {
    const api = await mockEABApi(page, seed());
    await page.goto('/ca/eab/1');

    await expect(page.getByRole('heading', { name: 'EAB Credential 1' })).toBeVisible();
    await expect(page.getByText('kid-active')).toBeVisible();
    await expect(page.getByTestId('eab-status')).toHaveText('ACTIVE');
    expect(api.calls.some((c) => c.method === 'GET' && c.path === '/1')).toBe(true);
  });

  test('resolves the id from the pathname on the exported placeholder page', async ({ page }) => {
    const api = await mockEABApi(page, seed());
    await openPlaceholderDetail(page, 1);

    await expect(page.getByRole('heading', { name: 'EAB Credential 1' })).toBeVisible();
    await expect(page.getByTestId('eab-status')).toHaveText('ACTIVE');
    expect(api.calls.some((c) => c.method === 'GET' && c.path === '/1')).toBe(true);
  });

  test('opens the detail page from the list', async ({ page }) => {
    await mockEABApi(page, seed());
    await page.goto('/ca/eab');

    await page.getByTestId('eab-row-1').getByRole('link', { name: '1' }).click();
    await expect(page).toHaveURL(/\/ca\/eab\/1\/?$/);
    await expect(page.getByRole('heading', { name: 'EAB Credential 1' })).toBeVisible();
  });

  test('shows the QR code (GetCredentialQRCode)', async ({ page }) => {
    const api = await mockEABApi(page, seed());
    await page.goto('/ca/eab/1');

    await page.getByRole('button', { name: 'Show QR Code' }).click();

    await expect(page.getByAltText('EAB enrollment QR code')).toBeVisible();
    expect(api.calls.some((c) => c.method === 'GET' && c.path === '/1/qrcode')).toBe(true);
  });

  test('shows the enrollment URL (GetEnrollmentURL)', async ({ page }) => {
    const api = await mockEABApi(page, seed());
    await page.goto('/ca/eab/1');

    await page.getByRole('button', { name: 'Get Enrollment URL' }).click();

    await expect(page.getByTestId('eab-enrollment-url')).toHaveText('/enroll?kid=kid-active');
    expect(api.calls.some((c) => c.method === 'GET' && c.path === '/1/url')).toBe(true);
  });

  test('marks a credential used (MarkCredentialUsed)', async ({ page }) => {
    const api = await mockEABApi(page, seed());
    await page.goto('/ca/eab/1');

    await page.getByRole('button', { name: 'Mark Used' }).click();

    await expect(page.getByTestId('eab-message')).toHaveText('Credential marked as used');
    await expect(page.getByTestId('eab-status')).toHaveText('USED');
    expect(api.calls.some((c) => c.method === 'POST' && c.path === '/1/used')).toBe(true);
  });

  test('shows an error for an unknown credential', async ({ page }) => {
    await mockEABApi(page, seed());
    await page.goto('/ca/eab/99');

    await expect(page.getByRole('alert')).toBeVisible();
  });
});
