import type { Page, Response } from '@playwright/test';
import type { EABCredential, PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * EAB credential pages against the real platformd (#2050, epic #1665): every
 * EABService operation is driven from /ca/eab or /ca/eab/[id]. Credentials are
 * seeded through the SDK and every case holds the page to the response the
 * server gave it; nothing is canned.
 */

function apiResponse(page: Page, method: string, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && path.test(new URL(r.url()).pathname),
  );
}

async function json<T>(r: Response): Promise<T> {
  expect(r.ok(), `${r.url()} answered ${r.status()}`).toBeTruthy();
  return unwrapPayload<T>(await r.json());
}

/** The status the pages show: the enum name without its prefix. */
function shownStatus(status: unknown): string {
  return String(status ?? '').replace(/^EAB_CREDENTIAL_STATUS_/, '');
}

/** The profile EAB credentials bind to; the server stores it as given. */
const PROFILE_ID = '1';

/** Create a credential through the SDK in the admin's tenant; returns it with its HMAC key. */
async function seed(sdk: PlatformClient, tenantId: string, expiresInSeconds = 3600): Promise<EABCredential> {
  const created = await sdk.eab.create({ profileId: PROFILE_ID, tenantId, expiresInSeconds });
  expect(created.success, JSON.stringify(created.error)).toBeTruthy();
  const cred = created.data?.credential;
  expect(cred?.id, 'the created credential carries an id').toBeTruthy();
  expect(cred?.keyId, 'the created credential carries a key id').toBeTruthy();
  return cred!;
}

const CREDENTIALS = /\/api\/v1\/eab\/credentials$/;

test.describe('EAB credentials - list page', () => {
  test('CreateCredential: the form creates a credential and shows its key id', async ({ adminPage, tenant }) => {
    await adminPage.goto('/ca/eab');
    await adminPage.getByLabel('Profile ID').fill(PROFILE_ID);
    await adminPage.getByLabel('Tenant ID').fill(tenant.id);
    await adminPage.getByLabel('Expires in (seconds)').fill('3600');
    const res = apiResponse(adminPage, 'POST', CREDENTIALS);
    await adminPage.getByRole('button', { name: 'Create', exact: true }).click();
    const body = await json<{ credential?: { keyId?: string } }>(await res);
    expect(body.credential?.keyId, 'the server returns the new key id').toBeTruthy();
    await expect(adminPage.getByTestId('eab-created')).toContainText(body.credential!.keyId!);
  });

  test("ListCredentials: an SDK-created credential's row shows its key id", async ({ adminPage, sdk, tenant }) => {
    const cred = await seed(sdk, tenant.id);
    await adminPage.goto('/ca/eab');
    await expect(adminPage.getByTestId(`eab-row-${cred.id}`)).toContainText(cred.keyId);
  });

  test('RevokeCredential: the row Revoke button revokes the credential', async ({ adminPage, sdk, tenant }) => {
    const cred = await seed(sdk, tenant.id);
    await adminPage.goto('/ca/eab');
    const row = adminPage.getByTestId(`eab-row-${cred.id}`);
    const res = apiResponse(adminPage, 'POST', new RegExp(`/eab/credentials/${cred.id}/revoke$`));
    await row.getByRole('button', { name: 'Revoke' }).click();
    await json<unknown>(await res);
    await expect(row).toContainText('REVOKED');
  });

  test('DeleteCredential: the row Delete button deletes the credential', async ({ adminPage, sdk, tenant }) => {
    const cred = await seed(sdk, tenant.id);
    await adminPage.goto('/ca/eab');
    const row = adminPage.getByTestId(`eab-row-${cred.id}`);
    await expect(row).toBeVisible();
    adminPage.once('dialog', (dialog) => void dialog.accept());
    const res = apiResponse(adminPage, 'DELETE', new RegExp(`/eab/credentials/${cred.id}$`));
    await row.getByRole('button', { name: 'Delete' }).click();
    await json<unknown>(await res);
    await expect(row).toHaveCount(0);
  });

  test("ValidateCredential: the form shows the server's verdict", async ({ adminPage, sdk, tenant }) => {
    const cred = await seed(sdk, tenant.id);
    await adminPage.goto('/ca/eab');
    const form = adminPage.locator('form', { has: adminPage.getByRole('button', { name: 'Validate' }) });
    await form.getByLabel('Key ID').fill(cred.keyId);
    await form.getByLabel('HMAC Key').fill(cred.hmacKey);
    const res = apiResponse(adminPage, 'POST', /\/eab\/credentials\/validate$/);
    await form.getByRole('button', { name: 'Validate' }).click();
    const body = await json<{ valid?: boolean }>(await res);
    await expect(adminPage.getByTestId('eab-validation')).toHaveText(body.valid === true ? 'Valid' : 'Invalid');
  });

  test('GetCredentialByKeyID: Look Up finds the credential by its key id', async ({ adminPage, sdk, tenant }) => {
    const cred = await seed(sdk, tenant.id);
    await adminPage.goto('/ca/eab');
    const form = adminPage.locator('form', { has: adminPage.getByRole('button', { name: 'Look Up' }) });
    await form.getByLabel('Key ID').fill(cred.keyId);
    const res = apiResponse(adminPage, 'GET', new RegExp(`/eab/credentials/key/${cred.keyId}$`));
    await form.getByRole('button', { name: 'Look Up' }).click();
    const body = await json<{ credential?: { id?: string } }>(await res);
    expect(body.credential?.id).toBe(cred.id);
    await expect(adminPage.getByTestId('eab-lookup-result')).toContainText(cred.id);
  });

  test('CleanupExpiredCredentials: Clean Up Expired shows the count the server gives', async ({ adminPage }) => {
    await adminPage.goto('/ca/eab');
    const res = apiResponse(adminPage, 'POST', /\/eab\/credentials\/cleanup$/);
    await adminPage.getByRole('button', { name: 'Clean Up Expired' }).click();
    const body = await json<{ deletedCount?: number | string }>(await res);
    await expect(adminPage.getByTestId('eab-message')).toHaveText(
      `Deleted ${Number(body.deletedCount ?? 0)} expired credentials`,
    );
  });
});

test.describe('EAB credentials - detail page', () => {
  test('GetCredential: the detail page shows the credential', async ({ adminPage, sdk, tenant }) => {
    const cred = await seed(sdk, tenant.id);
    const res = apiResponse(adminPage, 'GET', new RegExp(`/eab/credentials/${cred.id}$`));
    await adminPage.goto(`/ca/eab/${cred.id}`);
    const body = await json<{ credential?: { keyId?: string; status?: string } }>(await res);
    expect(body.credential?.keyId).toBe(cred.keyId);
    await expect(adminPage.getByRole('heading', { name: `EAB Credential ${cred.id}` })).toBeVisible();
    await expect(adminPage.getByText(cred.keyId)).toBeVisible();
    await expect(adminPage.getByTestId('eab-status')).toHaveText('ACTIVE');
  });

  test('GetCredentialQRCode: Show QR Code shows the image the server sent', async ({ adminPage, sdk, tenant }) => {
    const cred = await seed(sdk, tenant.id);
    await adminPage.goto(`/ca/eab/${cred.id}`);
    await expect(adminPage.getByTestId('eab-status')).toBeVisible();
    const res = apiResponse(adminPage, 'GET', new RegExp(`/eab/credentials/${cred.id}/qrcode$`));
    await adminPage.getByRole('button', { name: 'Show QR Code' }).click();
    const body = await json<{ qrCode?: string }>(await res);
    expect(body.qrCode, 'the server sends QR code data').toBeTruthy();
    const img = adminPage.getByAltText('EAB enrollment QR code');
    await expect(img).toBeVisible();
    const src = await img.getAttribute('src');
    expect(src).toContain(body.qrCode!.replace(/^data:[^,]*,/, ''));
  });

  test('GetEnrollmentURL: Get Enrollment URL shows the URL the server sent', async ({ adminPage, sdk, tenant }) => {
    const cred = await seed(sdk, tenant.id);
    await adminPage.goto(`/ca/eab/${cred.id}`);
    await expect(adminPage.getByTestId('eab-status')).toBeVisible();
    const res = apiResponse(adminPage, 'GET', new RegExp(`/eab/credentials/${cred.id}/url$`));
    await adminPage.getByRole('button', { name: 'Get Enrollment URL' }).click();
    const body = await json<{ url?: string }>(await res);
    expect(body.url, 'the server sends an enrollment URL').toBeTruthy();
    await expect(adminPage.getByTestId('eab-enrollment-url')).toHaveText(body.url!);
  });

  test('MarkCredentialUsed: Mark Used changes the status to what the server reports', async ({
    adminPage,
    sdk,
    tenant,
  }) => {
    const cred = await seed(sdk, tenant.id);
    await adminPage.goto(`/ca/eab/${cred.id}`);
    await expect(adminPage.getByTestId('eab-status')).toHaveText('ACTIVE');
    const res = apiResponse(adminPage, 'POST', new RegExp(`/eab/credentials/${cred.id}/used$`));
    await adminPage.getByRole('button', { name: 'Mark Used' }).click();
    await json<unknown>(await res);
    await expect(adminPage.getByTestId('eab-message')).toHaveText('Credential marked as used');

    const reread = await sdk.eab.get(cred.id);
    expect(reread.success, JSON.stringify(reread.error)).toBeTruthy();
    const after = shownStatus(reread.data?.credential.status);
    expect(after).not.toBe('ACTIVE');
    await expect(adminPage.getByTestId('eab-status')).toHaveText(after);
  });
});
