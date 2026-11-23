import type { Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * CA overview, sign and verify pages against the real platformd (#2041,
 * epic #1665). Every case seeds through the SDK and holds the page to the
 * response the server gave it; nothing is canned.
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

/** Issue a short-lived certificate through the SDK; returns its serial and PEM. */
async function issue(sdk: PlatformClient, prefix: string): Promise<{ serial: string; pem: string }> {
  const issued = await sdk.ca.issueCertificate({
    subject: { commonName: `${prefix}-${Date.now()}.localhost` },
    validDays: 1,
  });
  expect(issued.success, JSON.stringify(issued.error)).toBeTruthy();
  const cert = issued.data?.certificate;
  expect(cert?.pem, 'issued certificate carries a PEM').toBeTruthy();
  expect(cert?.serial, 'issued certificate carries a serial').toBeTruthy();
  return { serial: cert!.serial, pem: cert!.pem! };
}

const VERIFY_PATH = /\/ca\/certificates\/verify$/;

async function verify(page: Page, pem: string): Promise<Response> {
  await page.goto('/ca/verify');
  await page.getByLabel('Certificate (PEM)').fill(pem);
  const res = apiResponse(page, 'POST', VERIFY_PATH);
  await page.getByRole('button', { name: 'Verify', exact: true }).click();
  return res;
}

async function expectVerdict(page: Page, res: Response): Promise<void> {
  const body = await json<{ valid?: boolean }>(res);
  await expect(page.getByTestId('verify-result')).toHaveText(
    body.valid === true ? 'Certificate is valid' : 'Certificate is not valid',
  );
}

test.describe('CA operations', () => {
  test('GetCAInfo: the overview shows the CA the server reports', async ({ adminPage }) => {
    const infoRes = apiResponse(adminPage, 'GET', /\/api\/v1\/ca\/info$/);
    await adminPage.goto('/ca');
    const outer = await json<Record<string, unknown>>(await infoRes);
    const info = (outer.caInfo ?? outer.ca_info ?? outer) as {
      commonName?: string;
      defaultAlgorithm?: string;
    };
    expect(info.commonName, 'the server reports a CA common name').toBeTruthy();
    await expect(adminPage.getByTestId('ca-common-name')).toHaveText(info.commonName ?? '');
    await expect(adminPage.getByTestId('ca-default-algorithm')).toHaveText(info.defaultAlgorithm ?? '');
  });

  test('GetCAInfo: the overview links to the sign and verify pages', async ({ adminPage }) => {
    await adminPage.goto('/ca');
    await adminPage.getByTestId('ca-sign-link').click();
    await expect(adminPage).toHaveURL(/\/ca\/sign$/);
    await adminPage.goto('/ca');
    await adminPage.getByTestId('ca-verify-link').click();
    await expect(adminPage).toHaveURL(/\/ca\/verify$/);
  });

  test('VerifyCertificate: a certificate the CA issued is verified by the server', async ({ adminPage, sdk }) => {
    const { pem } = await issue(sdk, 'ca-verify');
    await expectVerdict(adminPage, await verify(adminPage, pem));

    // Editing the PEM drops the verdict for the old input.
    await adminPage.getByLabel('Certificate (PEM)').fill(`${pem}\n# edited`);
    await expect(adminPage.getByTestId('verify-result')).toHaveCount(0);
  });

  test("VerifyCertificate: a revoked certificate gets the server's verdict", async ({ adminPage, sdk }) => {
    const { serial, pem } = await issue(sdk, 'ca-revoked');
    const revoked = await sdk.ca.revokeCertificate({ serial, reason: 'KEY_COMPROMISE' });
    expect(revoked.success, JSON.stringify(revoked.error)).toBeTruthy();
    await expectVerdict(adminPage, await verify(adminPage, pem));
  });

  test("VerifyCertificate: input that is not a certificate shows the server's refusal", async ({ adminPage }) => {
    const res = await verify(adminPage, 'not a certificate');
    expect(res.ok(), `verify of a non-certificate answered ${res.status()}`).toBeFalsy();
    await expect(adminPage.getByTestId('verify-result')).toHaveCount(0);
  });

  test('SignCSR: a CSR with a token the server does not know is refused', async ({ adminPage }) => {
    await adminPage.goto('/ca/sign');
    await adminPage
      .getByLabel('CSR (PEM)')
      .fill('-----BEGIN CERTIFICATE REQUEST-----\nTUlJQmp1bmsK\n-----END CERTIFICATE REQUEST-----');
    await adminPage.getByLabel('Platform token').fill(`e2e-unknown-${Date.now()}`);
    const res = apiResponse(adminPage, 'POST', /\/ca\/sign-csr$/);
    await adminPage.getByRole('button', { name: 'Sign CSR' }).click();
    const answered = await res;
    expect(answered.ok(), `sign-csr with an unknown token answered ${answered.status()}`).toBeFalsy();
    await expect(adminPage.getByTestId('signed-serial')).toHaveCount(0);
    await expect(adminPage.getByTestId('signed-pem')).toHaveCount(0);
  });
});
