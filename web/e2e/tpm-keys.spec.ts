import { test, expect, Page } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import {
  mockTenantApi,
  mockTPMKeyOperationsApi,
  TPMKeyOperationCall,
  TPMKeyOperationReply,
} from './fixtures/api-mock';

/**
 * TPM key lifecycle page (#1735, slice 31 of #1665): provision, clear,
 * capabilities, platform attributes, EK/SRK/AK and quote operations.
 * Every request is answered by mockTPMKeyOperationsApi.
 */

const EK_HANDLE = 0x81010001;
const SRK_HANDLE = 0x81000001;
const AK_HANDLE = 0x81010002;

async function openKeysPage(
  page: Page,
  overrides: Record<string, TPMKeyOperationReply> = {},
): Promise<TPMKeyOperationCall[]> {
  await createTenantOwnerSession(page.context());
  await mockTenantApi(page);
  const calls = await mockTPMKeyOperationsApi(page, overrides);
  await page.goto('/tpm/keys');
  await expect(page.getByRole('heading', { name: /tpm keys/i })).toBeVisible();
  return calls;
}

function findCall(calls: TPMKeyOperationCall[], method: string, path: string): TPMKeyOperationCall | undefined {
  return calls.find((c) => c.method === method && c.path === path);
}

async function expectCall(calls: TPMKeyOperationCall[], method: string, path: string): Promise<TPMKeyOperationCall> {
  await expect.poll(() => findCall(calls, method, path) !== undefined).toBe(true);
  return findCall(calls, method, path) as TPMKeyOperationCall;
}

/** Clicks a destructive operation, checks Cancel sends nothing, then confirms. */
async function confirmDestructive(page: Page, calls: TPMKeyOperationCall[], op: string, method: string, path: string) {
  await page.getByTestId(`tpm-op-${op}`).click();
  await expect(page.getByTestId('tpm-confirm-dialog')).toBeVisible();
  await page.getByTestId('tpm-confirm-cancel').click();
  await expect(page.getByTestId('tpm-confirm-dialog')).toBeHidden();
  expect(findCall(calls, method, path)).toBeUndefined();

  await page.getByTestId(`tpm-op-${op}`).click();
  await page.getByTestId('tpm-confirm-ok').click();
  return expectCall(calls, method, path);
}

test.describe('TPM Keys operations', () => {
  test('Provision posts to /tpm/provision', async ({ page }) => {
    const calls = await openKeysPage(page);
    await page.getByLabel('Owner password').fill('owner-secret');
    await page.getByTestId('tpm-op-provision').click();

    const call = await expectCall(calls, 'POST', '/provision');
    expect(call.body).toMatchObject({ ownerPassword: 'owner-secret', createEk: true, createSrk: true, createAk: true });
    await expect(page.getByTestId('tpm-result-provision')).toContainText('provisioned');
  });

  test('Clear asks for confirmation and posts to /tpm/clear', async ({ page }) => {
    const calls = await openKeysPage(page);
    await page.getByLabel('Owner password').fill('owner-secret');

    const call = await confirmDestructive(page, calls, 'clear', 'POST', '/clear');
    expect(call.body).toMatchObject({ ownerPassword: 'owner-secret', confirm: true });
    await expect(page.getByTestId('tpm-result-clear')).toContainText('cleared');
  });

  test('GetCapabilities shows /tpm/capabilities', async ({ page }) => {
    const calls = await openKeysPage(page);
    await page.getByTestId('tpm-op-capabilities').click();

    await expectCall(calls, 'GET', '/capabilities');
    await expect(page.getByTestId('tpm-result-capabilities')).toContainText('TPM2_Certify');
    await expect(page.getByTestId('tpm-result-capabilities')).toContainText('NIST_P256');
  });

  test('GetPlatformAttributes shows /tpm/platform', async ({ page }) => {
    const calls = await openKeysPage(page);
    await page.getByTestId('tpm-op-platform').click();

    await expectCall(calls, 'GET', '/platform');
    await expect(page.getByTestId('tpm-result-platform')).toContainText('Mock TPM Vendor');
  });

  test('CreateEK posts to /tpm/ek', async ({ page }) => {
    const calls = await openKeysPage(page);
    await page.getByTestId('tpm-op-createEK').click();

    const call = await expectCall(calls, 'POST', '/ek');
    expect(call.body).toMatchObject({ persistent: true });
    await expect(page.getByTestId('tpm-result-createEK')).toContainText(String(EK_HANDLE));
  });

  test('ImportEKCertificate posts to /tpm/ek/certificate', async ({ page }) => {
    const calls = await openKeysPage(page);
    await expect(page.getByTestId('tpm-op-importEKCertificate')).toBeDisabled();

    const pem = '-----BEGIN CERTIFICATE-----\nTUlJQg==\n-----END CERTIFICATE-----';
    await page.getByLabel('EK certificate (PEM)').fill(pem);
    await page.getByTestId('tpm-op-importEKCertificate').click();

    const call = await expectCall(calls, 'POST', '/ek/certificate');
    // The server stores DER only: the PEM body (base64 DER) is sent as DER.
    expect(call.body).toMatchObject({ format: 'DER', certificate: 'TUlJQg==' });
    await expect(page.getByTestId('tpm-result-importEKCertificate')).toContainText('imported');
  });

  test('DeleteEK asks for confirmation and deletes /tpm/ek', async ({ page }) => {
    const calls = await openKeysPage(page);
    await confirmDestructive(page, calls, 'deleteEK', 'DELETE', `/ek/${EK_HANDLE}`);
    await expect(page.getByTestId('tpm-result-deleteEK')).toContainText('ek deleted');
  });

  test('CreateSRK posts to /tpm/srk', async ({ page }) => {
    const calls = await openKeysPage(page);
    await page.getByTestId('tpm-op-createSRK').click();

    const call = await expectCall(calls, 'POST', '/srk');
    expect(call.body).toMatchObject({ persistent: true });
    await expect(page.getByTestId('tpm-result-createSRK')).toContainText(String(SRK_HANDLE));
  });

  test('DeleteSRK asks for confirmation and deletes /tpm/srk', async ({ page }) => {
    const calls = await openKeysPage(page);
    await confirmDestructive(page, calls, 'deleteSRK', 'DELETE', `/srk/${SRK_HANDLE}`);
    await expect(page.getByTestId('tpm-result-deleteSRK')).toContainText('srk deleted');
  });

  test('CreateAK posts to /tpm/ak', async ({ page }) => {
    const calls = await openKeysPage(page);
    await page.getByTestId('tpm-op-createAK').click();

    const call = await expectCall(calls, 'POST', '/ak');
    expect(call.body).toMatchObject({ persistent: true });
    await expect(page.getByTestId('tpm-result-createAK')).toContainText(String(AK_HANDLE));
  });

  test('GetAK shows /tpm/ak', async ({ page }) => {
    const calls = await openKeysPage(page);
    await page.getByTestId('tpm-op-getAK').click();

    await expectCall(calls, 'GET', '/ak');
    await expect(page.getByTestId('tpm-result-getAK')).toContainText(String(AK_HANDLE));
  });

  test("DeleteAK asks for confirmation and shows the server's refusal", async ({ page }) => {
    const calls = await openKeysPage(page);
    await confirmDestructive(page, calls, 'deleteAK', 'DELETE', `/ak/${AK_HANDLE}`);
    await expect(page.getByTestId('tpm-error-deleteAK')).toContainText('not evicted');
    await expect(page.getByTestId('tpm-result-deleteAK')).toHaveCount(0);
  });

  test('Quote posts to /tpm/quote', async ({ page }) => {
    const calls = await openKeysPage(page);
    await page.getByLabel('PCRs to quote').fill('0, 7');
    await page.getByTestId('tpm-op-quote').click();

    const call = await expectCall(calls, 'POST', '/quote');
    expect(call.body).toMatchObject({ akHandle: AK_HANDLE, pcrIndices: [0, 7], pcrBank: 'PCR_BANK_SHA256' });
    expect((call.body as { nonce?: string }).nonce).toBeTruthy();
    await expect(page.getByTestId('tpm-result-quote')).toContainText('cXVvdGU=');
  });

  test('VerifyQuote posts to /tpm/quote/verify', async ({ page }) => {
    const calls = await openKeysPage(page);
    await expect(page.getByTestId('tpm-op-verifyQuote')).toBeDisabled();

    await page.getByTestId('tpm-op-quote').click();
    const quoteCall = await expectCall(calls, 'POST', '/quote');
    await expect(page.getByTestId('tpm-op-verifyQuote')).toBeEnabled();
    await page.getByTestId('tpm-op-verifyQuote').click();

    const call = await expectCall(calls, 'POST', '/quote/verify');
    expect(call.body).toMatchObject({
      quote: 'cXVvdGU=',
      signature: 'c2ln',
      signatureAlgorithm: 'ECDSA-SHA256',
      channelBinding: 'Y2I=',
      nonce: (quoteCall.body as { nonce: string }).nonce,
    });
    await expect(page.getByTestId('tpm-result-verifyQuote')).toContainText('quote verified');
  });

  test('VerifyQuote shows an invalid verdict for verified: false', async ({ page }) => {
    const calls = await openKeysPage(page, {
      'POST /quote/verify': { status: 200, body: { verified: false, message: 'nonce mismatch' } },
    });
    await page.getByTestId('tpm-op-quote').click();
    await expectCall(calls, 'POST', '/quote');
    await expect(page.getByTestId('tpm-op-verifyQuote')).toBeEnabled();
    await page.getByTestId('tpm-op-verifyQuote').click();

    await expectCall(calls, 'POST', '/quote/verify');
    await expect(page.getByTestId('tpm-verdict-verifyQuote')).toContainText('INVALID: nonce mismatch');
  });

  test('Certify posts to /tpm/certify', async ({ page }) => {
    const calls = await openKeysPage(page);
    await page.getByLabel('Key handle to certify').fill('0x81000001');
    await page.getByLabel('Key password (optional)').fill('key-secret');
    await page.getByTestId('tpm-op-certify').click();

    const call = await expectCall(calls, 'POST', '/certify');
    expect(call.body).toMatchObject({ keyHandle: SRK_HANDLE, keyPassword: 'key-secret' });
    await expect(page.getByTestId('tpm-result-certify')).toContainText('aW5mbw==');
  });

  test('a failed operation shows its error', async ({ page }) => {
    const calls = await openKeysPage(page, {
      'POST /certify': { status: 500, body: { message: 'certify refused', code: 'HTTP_500' } },
    });
    await page.getByTestId('tpm-op-certify').click();

    await expectCall(calls, 'POST', '/certify');
    await expect(page.getByTestId('tpm-error-certify')).toBeVisible();
    await expect(page.getByTestId('tpm-result-certify')).toHaveCount(0);
  });
});
