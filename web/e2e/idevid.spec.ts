import { test, expect, Page } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockIDevIDApi, mockTenantApi, IDevIDApiCall } from './fixtures/api-mock';

/**
 * TPM IDevID and IAK E2E Tests (#1672)
 *
 * Every IDevID/IAK backend operation is reachable from /tpm/idevid; each
 * test drives one operation against the mocked API and asserts the request
 * the page sent.
 */

const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';

async function openPage(page: Page, config: Parameters<typeof mockIDevIDApi>[1] = {}) {
  const mock = await mockIDevIDApi(page, config);
  await mockTenantApi(page);
  await page.goto('/tpm/idevid');
  await expect(page.getByRole('heading', { name: 'IDevID and IAK' })).toBeVisible();
  return mock;
}

function called(calls: IDevIDApiCall[], method: string, path: string) {
  return () => calls.filter((c) => c.method === method && c.path === path).length;
}

async function confirm(page: Page, button: string) {
  await page.getByRole('button', { name: button, exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Confirm' }).click();
}

test.describe('TPM IDevID and IAK', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('HasIDevID shows the IDevID status', async ({ page }) => {
    const { calls } = await openPage(page, { hasIDevID: true });
    await expect(page.getByTestId('idevid-status')).toHaveText('Present');
    expect(called(calls, 'GET', '/exists')()).toBeGreaterThan(0);
  });

  test('HasIAK shows the IAK status', async ({ page }) => {
    const { calls } = await openPage(page, { hasIAK: false });
    await expect(page.getByTestId('iak-status')).toHaveText('Absent');
    expect(called(calls, 'GET', '/iak/exists')()).toBeGreaterThan(0);
  });

  test('GetDeviceAttributes shows the device attributes', async ({ page }) => {
    await openPage(page);
    const attrs = page.getByTestId('device-attributes');
    await expect(attrs.getByText('Infineon')).toBeVisible();
    await expect(attrs.getByText('SN-0001')).toBeVisible();
  });

  test('GenerateIAK generates an IAK', async ({ page }) => {
    const { calls } = await openPage(page);
    await page.getByRole('button', { name: 'Generate IAK' }).click();
    await expect.poll(called(calls, 'POST', '/iak/generate')).toBe(1);
  });

  test('DeleteIAK deletes the IAK after confirmation', async ({ page }) => {
    const { calls } = await openPage(page);
    // Cancel first: nothing is deleted.
    await page.getByRole('button', { name: 'Delete IAK', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('dialog')).toBeHidden();
    expect(called(calls, 'DELETE', '/iak')()).toBe(0);

    await confirm(page, 'Delete IAK');
    await expect.poll(called(calls, 'DELETE', '/iak')).toBe(1);
  });

  test('CreateIAKCSR creates an IAK CSR', async ({ page }) => {
    const { calls } = await openPage(page);
    await page.getByRole('button', { name: 'Create IAK CSR' }).click();
    await expect.poll(called(calls, 'POST', '/iak/csr')).toBe(1);
    await expect(page.getByTestId('idevid-result')).toContainText('IAKCSR');
  });

  test('CreateLDevID creates an LDevID', async ({ page }) => {
    const { calls } = await openPage(page);
    await page.getByLabel('LDevID common name').fill('node-1');
    await page.getByRole('button', { name: 'Create LDevID' }).click();
    await expect.poll(called(calls, 'POST', '/ldevid')).toBe(1);
    const call = calls.find((c) => c.path === '/ldevid');
    expect(call?.body).toEqual({ template: { commonName: 'node-1' } });
    await expect(page.getByTestId('idevid-result')).toContainText('LDEVIDCERT');
  });

  test('InstallIDevIDCertificate installs a certificate', async ({ page }) => {
    const { calls } = await openPage(page);
    await page.getByLabel('IDevID certificate (PEM)').fill(PEM);
    await page.getByRole('button', { name: 'Install IDevID certificate' }).click();
    await expect.poll(called(calls, 'POST', '/certificate')).toBe(1);
    const call = calls.find((c) => c.method === 'POST' && c.path === '/certificate');
    const sent = (call?.body as { certificatePem: string }).certificatePem;
    expect(Buffer.from(sent, 'base64').toString()).toBe(PEM);
  });

  test('InstallIAKCertificate installs a certificate', async ({ page }) => {
    const { calls } = await openPage(page);
    await page.getByLabel('IAK certificate (PEM)').fill(PEM);
    await page.getByRole('button', { name: 'Install IAK certificate' }).click();
    await expect.poll(called(calls, 'POST', '/iak/certificate')).toBe(1);
  });

  test('DeleteIAKCertificate deletes the certificate after confirmation', async ({ page }) => {
    const { calls } = await openPage(page);
    await confirm(page, 'Delete IAK certificate');
    await expect.poll(called(calls, 'DELETE', '/iak/certificate')).toBe(1);
  });

  test('FlushTransientContexts flushes after confirmation', async ({ page }) => {
    const { calls } = await openPage(page);
    await confirm(page, 'Flush transient contexts');
    await expect.poll(called(calls, 'POST', '/flush')).toBe(1);
    await expect(page.getByTestId('idevid-result')).toContainText('Flushed 3 contexts');
  });

  test('ActivateCredential returns the secret', async ({ page }) => {
    const { calls } = await openPage(page);
    await page.getByLabel('Credential blob (base64)').fill('QkxPQg==');
    await page.getByLabel('Encrypted secret (base64)').fill('U0VD');
    await page.getByRole('button', { name: 'Activate credential' }).click();
    await expect.poll(called(calls, 'POST', '/activate-credential')).toBe(1);
    const call = calls.find((c) => c.path === '/activate-credential');
    expect(call?.body).toEqual({ credentialBlob: 'QkxPQg==', secret: 'U0VD' });
    await expect(page.getByTestId('idevid-result')).toContainText('U0VDUkVU');
  });
});
