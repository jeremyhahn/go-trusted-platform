import type { Response } from '@playwright/test';
import { test, expect } from './fixtures';

/**
 * CA operations (GetCAInfo, SignCSR, VerifyCertificate) against the
 * real-server harness (#2035). The CA info and the root certificate are read
 * through the SDK; the pages must show what the server returned.
 */

// Not a parseable CSR, and the token below carries no ca:sign-csr scope:
// the server must refuse it, whichever check it runs first.
const BAD_CSR_PEM = '-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----';
const UNSCOPED_TOKEN = 'tp_sign_csr_e2e_unscoped_token';

/** The message of a platform error envelope, in either of its two shapes. */
async function errorText(r: Response): Promise<string> {
  const b = (await r.json().catch(() => null)) as { error?: string | { message?: string } } | null;
  if (typeof b?.error === 'string') return b.error;
  return b?.error?.message ?? '';
}

function isPost(path: string) {
  return (r: Response) => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith(path);
}

test.describe('CA operations, real server', () => {
  test('GetCAInfo: the CA overview page shows the info the server returns', async ({ adminPage, sdk }) => {
    const info = await sdk.ca.getInfo();
    await adminPage.goto('/ca');
    await expect(adminPage.getByRole('heading', { name: 'Certificate Authority', exact: true })).toBeVisible();

    if (!info.success || !info.data?.caInfo) {
      await expect(adminPage.getByText(info.error?.message ?? 'error', { exact: false })).toBeVisible();
      return;
    }
    const ca = info.data.caInfo;
    await expect(adminPage.getByTestId('ca-common-name')).toHaveText(ca.commonName);
    await expect(adminPage.getByTestId('ca-default-algorithm')).toHaveText(ca.defaultAlgorithm);
    await expect(adminPage.getByTestId('ca-default-validity')).toHaveText(`${ca.defaultValidityDays} days`);
    if (ca.rootCert) await expect(adminPage.getByTestId('ca-root-cert')).toContainText(ca.rootCert.commonName);
    for (const intermediate of ca.intermediates ?? []) {
      await expect(adminPage.getByTestId('ca-intermediates')).toContainText(intermediate.commonName);
    }
  });

  test('GetCAInfo: the overview links to the sign and verify pages', async ({ adminPage }) => {
    await adminPage.goto('/ca');
    await adminPage.getByTestId('ca-sign-link').click();
    await expect(adminPage).toHaveURL(/\/ca\/sign/);
    await adminPage.goto('/ca');
    await adminPage.getByTestId('ca-verify-link').click();
    await expect(adminPage).toHaveURL(/\/ca\/verify/);
  });

  test('SignCSR: the page sends the CSR with the platform token, and shows the server refusal', async ({ adminPage }) => {
    await adminPage.goto('/ca/sign');
    await expect(adminPage.getByRole('heading', { name: 'Sign CSR', exact: true })).toBeVisible();
    await adminPage.getByLabel('CSR (PEM)').fill(BAD_CSR_PEM);
    await adminPage.getByLabel('Platform token').fill(UNSCOPED_TOKEN);
    await adminPage.getByLabel('Validity (days)').fill('30');

    const answer = adminPage.waitForResponse(isPost('/api/v1/ca/sign-csr'));
    await adminPage.getByRole('button', { name: 'Sign CSR' }).click();
    const res = await answer;

    expect(res.request().postDataJSON()).toMatchObject({ csrPem: BAD_CSR_PEM, validDays: 30 });
    // The server refuses a session without a ca:sign-csr platform token.
    expect(res.request().headers()['authorization']).toBe(`Bearer ${UNSCOPED_TOKEN}`);
    expect(res.ok()).toBe(false);
    const message = await errorText(res);
    expect(message).not.toBe('');
    await expect(adminPage.getByText(message)).toBeVisible();
    await expect(adminPage.getByTestId('signed-serial')).toHaveCount(0);
    await expect(adminPage.getByTestId('signed-pem')).toHaveCount(0);
  });

  test('VerifyCertificate: the root certificate gets the verdict the server returns', async ({ adminPage, sdk }) => {
    const root = await sdk.ca.getRootCertificate();
    const pem = root.data?.pem ?? '';
    test.skip(pem === '', 'the harness CA serves no root certificate PEM');

    await adminPage.goto('/ca/verify');
    await expect(adminPage.getByRole('heading', { name: 'Verify Certificate', exact: true })).toBeVisible();
    await adminPage.getByLabel('Certificate (PEM)').fill(pem);
    const answer = adminPage.waitForResponse(isPost('/api/v1/ca/certificates/verify'));
    await adminPage.getByRole('button', { name: 'Verify' }).click();
    const res = await answer;

    expect(res.request().postDataJSON()).toEqual({
      certificatePem: Buffer.from(pem).toString('base64'),
      verifyRevocation: true,
    });
    expect(res.ok()).toBe(true);
    const body = (await res.json()) as { payload?: { valid?: boolean; chain?: string[] }; valid?: boolean; chain?: string[] };
    const verdict = body.payload ?? body;
    await expect(adminPage.getByTestId('verify-result')).toHaveText(
      verdict.valid ? 'Certificate is valid' : 'Certificate is not valid'
    );
    for (const serial of verdict.chain ?? []) {
      await expect(adminPage.getByTestId('verify-chain')).toContainText(serial);
    }
    await expect(adminPage.getByTestId('verify-revocation')).toContainText('does not report whether');

    // Editing the input hides the verdict.
    await adminPage.getByLabel('Certificate (PEM)').fill(`${pem}\n# edited`);
    await expect(adminPage.getByTestId('verify-result')).toHaveCount(0);
  });

  test('VerifyCertificate: a refused request after a verdict hides the old verdict', async ({ adminPage, sdk }) => {
    const root = await sdk.ca.getRootCertificate();
    const pem = root.data?.pem ?? '';
    test.skip(pem === '', 'the harness CA serves no root certificate PEM');

    await adminPage.goto('/ca/verify');
    await adminPage.getByLabel('Certificate (PEM)').fill(pem);
    await adminPage.getByRole('button', { name: 'Verify' }).click();
    await expect(adminPage.getByTestId('verify-result')).toBeVisible();

    await adminPage.getByLabel('Certificate (PEM)').fill('not a certificate');
    const answer = adminPage.waitForResponse(isPost('/api/v1/ca/certificates/verify'));
    await adminPage.getByRole('button', { name: 'Verify' }).click();
    const res = await answer;

    if (!res.ok()) {
      const message = await errorText(res);
      if (message) await expect(adminPage.getByText(message)).toBeVisible();
      await expect(adminPage.getByTestId('verify-result')).toHaveCount(0);
      await expect(adminPage.getByTestId('verify-chain')).toHaveCount(0);
    } else {
      await expect(adminPage.getByTestId('verify-result')).toHaveText('Certificate is not valid');
    }
  });
});
