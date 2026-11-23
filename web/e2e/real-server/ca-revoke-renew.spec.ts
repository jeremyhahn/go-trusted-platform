import type { Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';

/**
 * Certificate revoke from the detail page and renew from the list, against
 * the real platformd (#2041, epic #1665). Each case seeds through the SDK,
 * drives the page's own control, then reads the result back through the SDK.
 */

function apiResponse(page: Page, method: string, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && path.test(new URL(r.url()).pathname),
  );
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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

test.describe('CA certificate revoke and renew', () => {
  test('Revoke from the certificate page revokes with the chosen reason', async ({ adminPage, sdk }) => {
    const { serial } = await issue(sdk, 'e2e-revoke');
    const escaped = escapeRegExp(encodeURIComponent(serial));

    const getRes = apiResponse(adminPage, 'GET', new RegExp(`/api/v1/ca/certificates/${escaped}$`));
    await adminPage.goto(`/ca/certificates/${encodeURIComponent(serial)}/`);
    expect((await getRes).ok()).toBeTruthy();

    // The page asks for the reason with a prompt and validates it.
    adminPage.once('dialog', (dialog) => dialog.accept('KEY_COMPROMISE'));
    const revokeRes = apiResponse(adminPage, 'DELETE', new RegExp(`/api/v1/ca/certificates/${escaped}$`));
    await adminPage.getByRole('button', { name: 'Revoke' }).click();
    const revoked = await revokeRes;
    expect(revoked.ok(), `revoke answered ${revoked.status()}`).toBeTruthy();

    const status = await sdk.ca.isRevoked(serial);
    expect(status.success, JSON.stringify(status.error)).toBeTruthy();
    expect(status.data?.revoked).toBe(true);
    expect(status.data?.reason).toBe('KEY_COMPROMISE');
  });

  test('Renew from the list renews the certificate', async ({ adminPage, sdk }) => {
    const { serial, commonName } = await issue(sdk, 'e2e-renew');

    const listRes = apiResponse(adminPage, 'GET', /\/api\/v1\/ca\/certificates$/);
    await adminPage.goto('/ca/certificates/');
    expect((await listRes).ok()).toBeTruthy();

    const row = adminPage.getByRole('row').filter({ hasText: commonName }).first();
    await expect(row).toBeVisible();
    await row.getByRole('button', { name: 'Open menu' }).click();

    // The page confirms the renewal before it sends it.
    adminPage.once('dialog', (dialog) => dialog.accept());
    const renewRes = apiResponse(
      adminPage,
      'POST',
      new RegExp(`/api/v1/ca/certificates/${escapeRegExp(encodeURIComponent(serial))}/renew$`),
    );
    await adminPage.getByRole('menuitem', { name: 'Renew' }).click();
    const renewed = await renewRes;
    expect(renewed.ok(), `renew answered ${renewed.status()}`).toBeTruthy();

    const listed = await sdk.ca.listCertificates();
    expect(listed.success, JSON.stringify(listed.error)).toBeTruthy();
    const sameSubject = (listed.data?.certificates ?? []).filter((c) =>
      JSON.stringify(c).includes(commonName),
    );
    const others = sameSubject.filter((c) => JSON.stringify(c).includes(serial) === false);
    expect(others.length, `a renewed certificate for ${commonName}`).toBeGreaterThan(0);
  });
});
