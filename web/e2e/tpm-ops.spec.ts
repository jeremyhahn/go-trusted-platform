import { test, expect } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockTenantApi, mockTPMOpsApi, TPMOpsCall } from './fixtures/api-mock';

/**
 * TPM operations e2e (slice 32 of #1665, issue #1725): GetEventLog,
 * ExtendPCR, MakeCredential, ActivateCredential and GetRandom.
 */
test.describe('TPM operations', () => {
  let calls: TPMOpsCall[];

  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
    await mockTenantApi(page);
    calls = await mockTPMOpsApi(page);
  });

  const callsTo = (path: string) => calls.filter((c) => c.path === path);

  test('GetEventLog: event log page loads the log', async ({ page }) => {
    await page.goto('/tpm/eventlog');

    await expect(page.getByRole('heading', { name: 'TPM Event Log' })).toBeVisible();
    await expect.poll(() => callsTo('/eventlog').length).toBeGreaterThan(0);
    expect(callsTo('/eventlog')[0].method).toBe('GET');
  });

  test('ExtendPCR: PCRs page extends a PCR after confirm', async ({ page }) => {
    await page.goto('/tpm/pcrs');

    await page.getByLabel('PCR index').fill('16');
    await page.getByLabel('Data', { exact: true }).fill('measure-me');
    await page.getByRole('button', { name: 'Extend PCR' }).click();

    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Extend PCR 16?')).toBeVisible();
    await dialog.getByRole('button', { name: 'Confirm' }).click();

    await expect.poll(() => callsTo('/pcrs/extend').length).toBe(1);
    expect(callsTo('/pcrs/extend')[0].body).toEqual({
      index: 16,
      hashAlg: 'SHA256',
      data: btoa('measure-me'),
    });
  });

  test('ExtendPCR: cancel sends nothing', async ({ page }) => {
    await page.goto('/tpm/pcrs');

    await page.getByLabel('Data', { exact: true }).fill('measure-me');
    await page.getByRole('button', { name: 'Extend PCR' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();

    await expect(page.getByRole('dialog')).toBeHidden();
    expect(callsTo('/pcrs/extend')).toHaveLength(0);
  });

  test('MakeCredential: credential page makes a credential', async ({ page }) => {
    await page.goto('/tpm/credential');

    await page.getByLabel('AK name (base64)').fill('AAsAAQ==');
    await page.getByLabel('Secret (optional)').fill('s3cret');
    await page.getByRole('button', { name: 'Make Credential' }).click();

    await expect.poll(() => callsTo('/make-credential').length).toBe(1);
    expect(callsTo('/make-credential')[0].body).toEqual({
      akName: 'AAsAAQ==',
      secret: btoa('s3cret'),
    });
    await expect(page.getByLabel('Credential blob (base64)')).toHaveValue(btoa('blob'));
    await expect(page.getByLabel('Encrypted secret (base64)')).toHaveValue(btoa('enc'));
  });

  test('ActivateCredential: credential page activates after confirm', async ({ page }) => {
    await page.goto('/tpm/credential');

    await page.getByLabel('Credential blob (base64)').fill(btoa('blob'));
    await page.getByLabel('Encrypted secret (base64)').fill(btoa('enc'));
    await page.getByRole('button', { name: 'Activate Credential' }).click();

    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Activate this credential?')).toBeVisible();
    expect(callsTo('/activate-credential')).toHaveLength(0);
    await dialog.getByRole('button', { name: 'Confirm' }).click();

    await expect.poll(() => callsTo('/activate-credential').length).toBe(1);
    expect(callsTo('/activate-credential')[0].body).toEqual({
      credentialBlob: btoa('blob'),
      encryptedSecret: btoa('enc'),
    });
    await expect(page.getByTestId('activated-secret')).toHaveText('010203');
  });

  test('GetRandom: credential page returns random bytes', async ({ page }) => {
    await page.goto('/tpm/credential');

    await page.getByLabel('Number of bytes').fill('4');
    await page.getByRole('button', { name: 'Get Random' }).click();

    await expect.poll(() => callsTo('/random').length).toBe(1);
    expect(callsTo('/random')[0].body).toEqual({ numBytes: 4 });
    await expect(page.getByTestId('random-bytes')).toHaveText('deadbeef');
  });

  test('credential page is linked from the TPM nav', async ({ page }) => {
    await page.goto('/tpm/pcrs');

    const link = page.getByRole('link', { name: 'Credential / Random' });
    await expect(link).toHaveAttribute('href', '/tpm/credential');
  });
});
