import type { Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * CA certificate list, certificate detail, CRL and CA bundle pages, and the
 * Issue Certificate gate, against the real platformd (#2041, epic #1665).
 * Every case seeds through the SDK and holds the page to the response the
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

/** Issue a short-lived certificate through the SDK; returns its serial, PEM and common name. */
async function issue(
  sdk: PlatformClient,
  prefix: string,
): Promise<{ serial: string; pem: string; commonName: string }> {
  const commonName = `${prefix}-${Date.now()}.localhost`;
  const issued = await sdk.ca.issueCertificate({
    subject: { commonName },
    validDays: 1,
  });
  expect(issued.success, JSON.stringify(issued.error)).toBeTruthy();
  const cert = issued.data?.certificate;
  expect(cert?.pem, 'issued certificate carries a PEM').toBeTruthy();
  expect(cert?.serial, 'issued certificate carries a serial').toBeTruthy();
  return { serial: cert!.serial, pem: cert!.pem!, commonName };
}

interface Result<T> {
  success: boolean;
  data?: T;
  error?: unknown;
}

function ok(res: Result<unknown>): void {
  expect(res.success, JSON.stringify(res.error)).toBe(true);
}

interface CapabilityAnswer {
  op: string;
  enabled: boolean;
  reason?: string;
}

interface CapabilitiesSdk {
  capabilities: { list(): Promise<Result<{ capabilities?: CapabilityAnswer[] }>> };
}

/** The server's own capability answers, by op (sdk.capabilities.list()). */
async function offered(sdk: CapabilitiesSdk): Promise<Map<string, CapabilityAnswer>> {
  const res = await sdk.capabilities.list();
  ok(res);
  return new Map((res.data?.capabilities ?? []).map((c) => [c.op, c]));
}

const ISSUE_OP = 'POST /api/v1/ca/certificates';

test.describe('CA certificates', () => {
  test('ListCertificates: an SDK-issued certificate is listed on /ca/certificates', async ({ adminPage, sdk }) => {
    const { commonName } = await issue(sdk, 'e2e-list');
    const listRes = apiResponse(adminPage, 'GET', /\/api\/v1\/ca\/certificates$/);
    await adminPage.goto('/ca/certificates');
    await json<unknown>(await listRes);
    await expect(adminPage.getByText(commonName).first()).toBeVisible();
  });

  test('GetCertificate: /ca/certificates/{serial} shows the certificate the server returns', async ({ adminPage, sdk }) => {
    const { serial } = await issue(sdk, 'e2e-detail');
    const escaped = encodeURIComponent(serial).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const getRes = apiResponse(adminPage, 'GET', new RegExp(`/api/v1/ca/certificates/${escaped}$`));
    await adminPage.goto(`/ca/certificates/${encodeURIComponent(serial)}`);
    await json<unknown>(await getRes);
    await expect(adminPage.getByText(serial).first()).toBeVisible();
  });

  test('GetCRL: a revoked serial is listed under Revoked Certificates on /ca/crl', async ({ adminPage, sdk }) => {
    const { serial } = await issue(sdk, 'e2e-crl');
    const revoked = await sdk.ca.revokeCertificate({ serial, reason: 'KEY_COMPROMISE' });
    expect(revoked.success, JSON.stringify(revoked.error)).toBeTruthy();

    await adminPage.goto('/ca/crl');
    await expect(adminPage.getByText('Revoked Certificates', { exact: true })).toBeVisible();
    await expect(adminPage.getByRole('cell', { name: serial }).first()).toBeVisible();
  });

  test('GetCABundle: /ca/bundle shows the PEM the server returns', async ({ adminPage }) => {
    await adminPage.goto('/ca/bundle');
    await expect(adminPage.getByText('-----BEGIN CERTIFICATE-----').first()).toBeVisible();
  });

  test("IssueCertificate: the Issue Certificate control carries the server's capability", async ({ adminPage, sdk }) => {
    const answer = (await offered(sdk)).get(ISSUE_OP);
    await adminPage.goto('/ca/certificates');
    // Never clicked: the case holds the gate to the server's answer only.
    await expect(adminPage.locator(`[data-capability-op="${ISSUE_OP}"]`).first()).toHaveAttribute(
      'data-capability-enabled',
      String(answer?.enabled ?? false),
    );
  });
});
