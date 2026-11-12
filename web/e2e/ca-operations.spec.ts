import { test, expect } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockTenantApi, mockCAOperationsApi } from './fixtures/api-mock';

const CSR_PEM = '-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----';
const CERT_PEM = '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----';

test.describe('CA operations', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
    await mockTenantApi(page);
  });

  test('GetCAInfo: the CA overview page shows the CA info', async ({ page }) => {
    await mockCAOperationsApi(page);
    await page.goto('/ca');

    await expect(page.getByRole('heading', { name: 'Certificate Authority', exact: true })).toBeVisible();
    await expect(page.getByTestId('ca-common-name')).toHaveText('Platform Intermediate CA');
    await expect(page.getByTestId('ca-default-algorithm')).toHaveText('ECDSA-P256');
    await expect(page.getByTestId('ca-default-validity')).toHaveText('397 days');
    await expect(page.getByTestId('ca-root-cert')).toContainText('Platform Root CA');
    await expect(page.getByTestId('ca-intermediates')).toContainText('Platform Intermediate CA');
  });

  test('GetCAInfo: the CA overview page shows an error', async ({ page }) => {
    // 400, not 500: the SDK retries a 500.
    await mockCAOperationsApi(page, { infoError: { error: 'CA not initialized', status: 400 } });
    await page.goto('/ca');

    await expect(page.getByText('CA not initialized')).toBeVisible();
  });

  test('GetCAInfo: the overview links to the sign and verify pages', async ({ page }) => {
    await mockCAOperationsApi(page);
    await page.goto('/ca');

    await page.getByTestId('ca-sign-link').click();
    await expect(page).toHaveURL(/\/ca\/sign/);
    await page.goto('/ca');
    await page.getByTestId('ca-verify-link').click();
    await expect(page).toHaveURL(/\/ca\/verify/);
  });

  test('SignCSR: the sign page submits a CSR and shows the certificate', async ({ page }) => {
    const mock = await mockCAOperationsApi(page);
    await page.goto('/ca/sign');

    await expect(page.getByRole('heading', { name: 'Sign CSR', exact: true })).toBeVisible();
    await page.getByLabel('CSR (PEM)').fill(CSR_PEM);
    await page.getByLabel('Validity (days)').fill('30');
    await page.getByRole('button', { name: 'Sign CSR' }).click();

    await expect(page.getByTestId('signed-serial')).toHaveText('0a1b2c');
    await expect(page.getByTestId('signed-pem')).toContainText('BEGIN CERTIFICATE');
    expect(mock.signRequests).toEqual([{ csrPem: CSR_PEM, validDays: 30 }]);
  });

  test('SignCSR: the sign page shows a refusal', async ({ page }) => {
    await mockCAOperationsApi(page, {
      signError: { error: 'token lacks scope ca:sign-csr', status: 403 },
    });
    await page.goto('/ca/sign');

    await page.getByLabel('CSR (PEM)').fill(CSR_PEM);
    await page.getByRole('button', { name: 'Sign CSR' }).click();

    await expect(page.getByText('token lacks scope ca:sign-csr')).toBeVisible();
  });

  test('VerifyCertificate: the verify page reports a valid certificate', async ({ page }) => {
    const mock = await mockCAOperationsApi(page);
    await page.goto('/ca/verify');

    await expect(page.getByRole('heading', { name: 'Verify Certificate', exact: true })).toBeVisible();
    await page.getByLabel('Certificate (PEM)').fill(CERT_PEM);
    await page.getByRole('button', { name: 'Verify' }).click();

    await expect(page.getByTestId('verify-result')).toHaveText('Certificate is valid');
    await expect(page.getByTestId('verify-chain')).toContainText('0a1b2c');
    await expect(page.getByTestId('verify-revocation')).toBeVisible();
    expect(mock.verifyRequests).toEqual([
      { certificatePem: Buffer.from(CERT_PEM).toString('base64'), verifyRevocation: true },
    ]);
  });

  test('VerifyCertificate: a revoked certificate is reported as not valid', async ({ page }) => {
    await mockCAOperationsApi(page, { verifyRevoked: true });
    await page.goto('/ca/verify');

    await page.getByLabel('Certificate (PEM)').fill(CERT_PEM);
    await page.getByRole('button', { name: 'Verify' }).click();

    await expect(page.getByTestId('verify-result')).toHaveText('Certificate is not valid');
    await expect(page.getByText('certificate is revoked')).toBeVisible();
  });

  test('VerifyCertificate: a failed request after a valid one hides the old verdict', async ({ page }) => {
    await mockCAOperationsApi(page);
    await page.goto('/ca/verify');

    await page.getByLabel('Certificate (PEM)').fill(CERT_PEM);
    await page.getByRole('button', { name: 'Verify' }).click();
    await expect(page.getByTestId('verify-result')).toHaveText('Certificate is valid');

    await page.getByLabel('Certificate (PEM)').fill('not a certificate');
    await page.getByRole('button', { name: 'Verify' }).click();

    await expect(page.getByText('certificatePem must be base64')).toBeVisible();
    await expect(page.getByTestId('verify-result')).toHaveCount(0);
    await expect(page.getByTestId('verify-chain')).toHaveCount(0);
  });

  test('VerifyCertificate: editing the input hides the previous verdict', async ({ page }) => {
    await mockCAOperationsApi(page);
    await page.goto('/ca/verify');

    await page.getByLabel('Certificate (PEM)').fill(CERT_PEM);
    await page.getByRole('button', { name: 'Verify' }).click();
    await expect(page.getByTestId('verify-result')).toHaveText('Certificate is valid');

    await page.getByLabel('Certificate (PEM)').fill(`${CERT_PEM}\n# edited`);
    await expect(page.getByTestId('verify-result')).toHaveCount(0);
  });

  test('VerifyCertificate: the verify page reports an invalid certificate', async ({ page }) => {
    await mockCAOperationsApi(page, { verifyValid: false });
    await page.goto('/ca/verify');

    await page.getByLabel('Certificate (PEM)').fill(CERT_PEM);
    await page.getByRole('button', { name: 'Verify' }).click();

    await expect(page.getByTestId('verify-result')).toHaveText('Certificate is not valid');
    await expect(page.getByText('certificate has expired')).toBeVisible();
  });
});
