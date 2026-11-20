/**
 * EAB credentials against the real server (#2050, coverage-matrix slice 13).
 *
 * Every EABService operation is driven from the dashboard pages `/ca/eab` and
 * `/ca/eab/[id]`; state is seeded through the SDK client the harness hands
 * out, and each test asserts on what the server returns, never on a mock.
 */
import type { Dialog, Page } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';
import { normalizeEABStatus } from '../../src/utils/eab-status';

// A CA profile the harness server knows; the seeded server's first profile
// unless the harness names another one.
const PROFILE_ID = process.env.E2E_EAB_PROFILE_ID ?? '1';

type Seeded = { id: string; keyId: string; hmacKey: string };

type SDK = PlatformClient;

// The harness fixtures (web/e2e/real-server/fixtures, #2034), typed here so
// the spec checks on its own.
type Fx = { adminPage: Page; sdk: SDK; tenant: { id: string; name: string } };

async function seed(sdk: SDK, tenantId: string, expiresInSeconds?: number): Promise<Seeded> {
  const res = await sdk.eab.create({
    profileId: PROFILE_ID,
    tenantId,
    ...(expiresInSeconds !== undefined ? { expiresInSeconds } : {}),
  });
  expect(res.success, JSON.stringify(res.error)).toBe(true);
  const cred = res.data?.credential;
  if (!cred) throw new Error('CreateCredential returned no credential');
  return { id: String(cred.id), keyId: cred.keyId, hmacKey: cred.hmacKey };
}

async function serverStatus(sdk: SDK, id: string): Promise<string | null> {
  const res = await sdk.eab.get(id);
  if (!res.success || !res.data) return null;
  return normalizeEABStatus(res.data.credential.status);
}

async function openList(page: Page) {
  await page.goto('/ca/eab');
  await expect(page.getByRole('heading', { name: 'EAB Credentials' })).toBeVisible();
}

test.describe('EAB credentials (real server)', () => {
  test('ListCredentials: the list shows a credential seeded through the SDK', async ({
    adminPage,
    sdk,
    tenant,
  }: Fx) => {
    const cred = await seed(sdk, tenant.id);
    await openList(adminPage);
    const row = adminPage.getByTestId(`eab-row-${cred.id}`);
    await expect(row).toBeVisible();
    await expect(row).toContainText(cred.keyId);
    await expect(row).toContainText('ACTIVE');
  });

  test('CreateCredential: the create form stores a credential the server returns by key ID', async ({
    adminPage,
    sdk,
    tenant,
  }: Fx) => {
    await openList(adminPage);
    await adminPage.getByLabel('Profile ID').fill(PROFILE_ID);
    await adminPage.getByLabel('Tenant ID').fill(tenant.id);
    await adminPage.getByLabel('Expires in (seconds)').fill('3600');
    await adminPage.getByRole('button', { name: 'Create' }).click();

    const created = adminPage.getByTestId('eab-created');
    await expect(created).toBeVisible();
    const keyId = (await created.locator('span.font-mono').first().innerText()).trim();
    expect(keyId).not.toBe('');

    const res = await sdk.eab.getByKeyId(keyId);
    expect(res.success).toBe(true);
    expect(res.data?.credential.tenantId).toBe(tenant.id);
    await expect(adminPage.getByTestId(`eab-row-${res.data!.credential.id}`)).toBeVisible();
  });

  test('ValidateCredential: a seeded key ID and HMAC key validate, a wrong HMAC key does not', async ({
    adminPage,
    sdk,
    tenant,
  }: Fx) => {
    const cred = await seed(sdk, tenant.id);
    await openList(adminPage);
    await adminPage.locator('#eab-validate-key-id').fill(cred.keyId);
    await adminPage.locator('#eab-validate-hmac').fill(cred.hmacKey);
    await adminPage.getByRole('button', { name: 'Validate' }).click();
    await expect(adminPage.getByTestId('eab-validation')).toHaveText('Valid');

    await adminPage.locator('#eab-validate-hmac').fill(`${cred.hmacKey}x`);
    await adminPage.getByRole('button', { name: 'Validate' }).click();
    await expect(adminPage.getByTestId('eab-validation')).toHaveText('Invalid');
  });

  test('GetCredentialByKeyID: the lookup form finds a seeded credential', async ({
    adminPage,
    sdk,
    tenant,
  }: Fx) => {
    const cred = await seed(sdk, tenant.id);
    await openList(adminPage);
    await adminPage.locator('#eab-lookup-key-id').fill(cred.keyId);
    await adminPage.getByRole('button', { name: 'Look Up' }).click();
    const result = adminPage.getByTestId('eab-lookup-result');
    await expect(result).toContainText(`Credential ${cred.id}`);
    await expect(result).toContainText(`Tenant: ${tenant.id}`);
  });

  test('RevokeCredential: revoking from the list revokes it on the server', async ({
    adminPage,
    sdk,
    tenant,
  }: Fx) => {
    const cred = await seed(sdk, tenant.id);
    await openList(adminPage);
    const row = adminPage.getByTestId(`eab-row-${cred.id}`);
    await row.getByRole('button', { name: 'Revoke' }).click();
    await expect(adminPage.getByTestId('eab-message')).toHaveText(`Credential ${cred.id} revoked`);
    await expect(row).toContainText('REVOKED');
    expect(await serverStatus(sdk, cred.id)).toBe('REVOKED');
  });

  test('DeleteCredential: deleting from the list removes it from the server', async ({
    adminPage,
    sdk,
    tenant,
  }: Fx) => {
    const cred = await seed(sdk, tenant.id);
    await openList(adminPage);
    adminPage.once('dialog', (d: Dialog) => void d.accept());
    await adminPage.getByTestId(`eab-row-${cred.id}`).getByRole('button', { name: 'Delete' }).click();
    await expect(adminPage.getByTestId('eab-message')).toHaveText(`Credential ${cred.id} deleted`);
    await expect(adminPage.getByTestId(`eab-row-${cred.id}`)).toHaveCount(0);
    expect(await serverStatus(sdk, cred.id)).toBeNull();
  });

  test('CleanupExpiredCredentials: clean up removes an expired credential from the server', async ({
    adminPage,
    sdk,
    tenant,
  }: Fx) => {
    const cred = await seed(sdk, tenant.id, 1);
    await adminPage.waitForTimeout(2_000);
    await openList(adminPage);
    await adminPage.getByRole('button', { name: 'Clean Up Expired' }).click();
    await expect(adminPage.getByTestId('eab-message')).toHaveText(/^Deleted [1-9][0-9]* expired credentials$/);
    expect(await serverStatus(sdk, cred.id)).toBeNull();
  });

  test('GetCredential: the detail page shows the credential the server returns', async ({
    adminPage,
    sdk,
    tenant,
  }: Fx) => {
    const cred = await seed(sdk, tenant.id);
    await adminPage.goto(`/ca/eab/${cred.id}`);
    await expect(adminPage.getByRole('heading', { name: `EAB Credential ${cred.id}` })).toBeVisible();
    await expect(adminPage.getByText(cred.keyId)).toBeVisible();
    await expect(adminPage.getByTestId('eab-status')).toHaveText('ACTIVE');
  });

  test('GetCredentialQRCode: the detail page renders the server QR code', async ({
    adminPage,
    sdk,
    tenant,
  }: Fx) => {
    const cred = await seed(sdk, tenant.id);
    await adminPage.goto(`/ca/eab/${cred.id}`);
    await adminPage.getByRole('button', { name: 'Show QR Code' }).click();
    const img = adminPage.getByAltText('EAB enrollment QR code');
    await expect(img).toBeVisible();
    await expect(img).toHaveAttribute('src', /^data:image\//);
  });

  test('GetEnrollmentURL: the detail page shows the server enrollment URL', async ({
    adminPage,
    sdk,
    tenant,
  }: Fx) => {
    const cred = await seed(sdk, tenant.id);
    const server = await sdk.eab.getEnrollmentURL(cred.id);
    expect(server.success).toBe(true);
    await adminPage.goto(`/ca/eab/${cred.id}`);
    await adminPage.getByRole('button', { name: 'Get Enrollment URL' }).click();
    await expect(adminPage.getByTestId('eab-enrollment-url')).toHaveText(server.data!.url);
  });

  test('MarkCredentialUsed: mark used on the detail page marks it used on the server', async ({
    adminPage,
    sdk,
    tenant,
  }: Fx) => {
    const cred = await seed(sdk, tenant.id);
    await adminPage.goto(`/ca/eab/${cred.id}`);
    await adminPage.getByRole('button', { name: 'Mark Used' }).click();
    await expect(adminPage.getByTestId('eab-message')).toHaveText('Credential marked as used');
    await expect(adminPage.getByTestId('eab-status')).toHaveText('USED');
    expect(await serverStatus(sdk, cred.id)).toBe('USED');
  });
});
