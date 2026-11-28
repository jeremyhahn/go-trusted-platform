import type { Page, Response } from '@playwright/test';
import { test, expect } from './fixtures';

/**
 * Certificate Authority pages (certificates, details, requests, CRL, bundle)
 * against the real-server harness (#2035).
 *
 * The certificates are the ones the harness CA holds: the SDK lists them, the
 * issue case adds one through the page, and each case asserts the page shows
 * what the server returned. Cases that need a scripted CA answer (a 409 on
 * issue, a 500 on revoke, a pending CSR queue, an expired certificate) are
 * gaps in the PR body.
 */

const CERTS = '/api/v1/ca/certificates';

interface ListedCert {
  serial: string;
  commonName: string;
  status: string;
}

interface CertLister {
  ca: {
    listCertificates(): Promise<{
      success: boolean;
      data?: { certificates?: Array<{ serial: string; commonName: string; status: unknown }> };
    }>;
    getCRL(): Promise<{ success: boolean; data?: { crl?: { revokedCerts?: Array<{ serial: string }> } } }>;
  };
}

async function listCerts(sdk: CertLister): Promise<ListedCert[]> {
  // A failed read fails the test: it is not an empty listing.
  const res = await sdk.ca.listCertificates();
  expect(res.success, 'GET /api/v1/ca/certificates').toBe(true);
  return (res.data?.certificates ?? []).map((c) => ({
    serial: c.serial,
    commonName: c.commonName,
    status: String(c.status).toUpperCase(),
  }));
}

function isRevoked(c: ListedCert): boolean {
  return c.status.includes('REVOKED');
}

/** The server's summary status for a valid certificate (an exact match: INVALID is not valid). */
function isValid(c: ListedCert): boolean {
  return c.status === 'CERTIFICATE_STATUS_VALID' || c.status === 'VALID';
}

/** A serial in one form on both sides: lowercase, no colons, no leading zeros. */
function normSerial(serial: string): string {
  return serial.toLowerCase().replace(/:/g, '').replace(/^0+(?=.)/, '');
}

/** The serials the CA's CRL (GET /ca/crl) lists as revoked; empty on a failed read. */
async function crlSerials(sdk: CertLister): Promise<Set<string>> {
  // A failed read fails the test: it is not an empty CRL.
  const res = await sdk.ca.getCRL();
  expect(res.success, 'GET /api/v1/ca/crl').toBe(true);
  return new Set((res.data?.crl?.revokedCerts ?? []).map((e) => normSerial(e.serial)));
}

function isCertList(r: Response): boolean {
  return r.request().method() === 'GET' && new URL(r.url()).pathname === CERTS;
}

/** Opens the static-export detail page for a serial and returns its GET. */
async function openDetail(page: Page, serial: string): Promise<Response> {
  const read = page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === `${CERTS}/${encodeURIComponent(serial)}`
  );
  await page.goto('/ca/certificates/__placeholder__/');
  await page.waitForLoadState('networkidle');
  await page.evaluate((s) => window.history.pushState(null, '', `/ca/certificates/${s}/`), serial);
  return read;
}

async function openRowMenu(page: Page, commonName: string): Promise<void> {
  const row = page.getByRole('row').filter({ hasText: commonName }).first();
  await row.getByRole('button', { name: /open menu/i }).click();
}

/** Issues one certificate through the page; returns its common name and the server answer. */
/** The message of the server's error envelope, in either shape. */
function serverMessage(body: unknown): string {
  const b = body as { error?: string | { message?: string } } | null;
  if (typeof b?.error === 'string') return b.error;
  return b?.error?.message ?? '';
}

async function issueThroughPage(page: Page): Promise<{ commonName: string; res: Response; alerts: string[] }> {
  const commonName = `e2e-${Date.now()}-${Math.floor(Math.random() * 1e6)}.example.com`;
  // Revoke asks prompt('Enter revocation reason:') and returns on an empty
  // answer, so a prompt gets a reason; the alerts and confirms are accepted.
  // Every dialog's message is recorded, so a test can assert what the
  // console told the user.
  const alerts: string[] = [];
  page.on('dialog', (d) => {
    alerts.push(d.message());
    (d.type() === 'prompt' ? d.accept('UNSPECIFIED') : d.accept()).catch(() => undefined);
  });
  await page.goto('/ca/certificates');
  await page.getByRole('button', { name: /issue certificate/i }).first().click();
  const dialog = page.getByRole('dialog');
  await page.locator('#subject').fill(`CN=${commonName},O=E2E`);
  const answer = page.waitForResponse((r) => r.request().method() === 'POST' && new URL(r.url()).pathname === CERTS);
  await dialog.getByRole('button', { name: /issue certificate/i }).click();
  return { commonName, res: await answer, alerts };
}

test.describe('Certificate Authority - Certificates Page, real server', () => {
  test('the table shows every certificate the server lists', async ({ adminPage, sdk }) => {
    const list = adminPage.waitForResponse(isCertList);
    await adminPage.goto('/ca/certificates');
    const res = await list;
    await expect(adminPage.getByRole('heading', { name: /certificates/i }).first()).toBeVisible();
    await expect(adminPage.locator('table')).toBeVisible();

    if (!res.ok()) return;
    for (const cert of (await listCerts(sdk)).slice(0, 10)) {
      await expect(adminPage.getByText(cert.commonName).first()).toBeVisible();
    }
  });

  test('a failed listing shows the server error', async ({ adminPage }) => {
    const list = adminPage.waitForResponse(isCertList);
    await adminPage.goto('/ca/certificates');
    const res = await list;
    test.skip(res.ok(), 'the harness CA answered the listing');
    await expect(adminPage.getByRole('main').getByText(/error|failed/i).first()).toBeVisible();
  });

  test('search filters the listed certificates', async ({ adminPage, sdk }) => {
    const certs = await listCerts(sdk);
    test.skip(certs.length === 0, 'the harness CA lists no certificate');
    await adminPage.goto('/ca/certificates');
    await expect(adminPage.getByText(certs[0].commonName).first()).toBeVisible();
    await adminPage.getByRole('main').getByPlaceholder(/search/i).fill(certs[0].commonName);
    await expect(adminPage.getByText(certs[0].commonName).first()).toBeVisible();
    for (const other of certs.slice(1).filter((c) => !c.commonName.includes(certs[0].commonName))) {
      await expect(adminPage.getByRole('row').filter({ hasText: other.commonName })).toHaveCount(0);
    }
  });

  test('View details opens the certificate the row lists', async ({ adminPage, sdk }) => {
    const certs = await listCerts(sdk);
    test.skip(certs.length === 0, 'the harness CA lists no certificate');
    await adminPage.goto('/ca/certificates');
    await openRowMenu(adminPage, certs[0].commonName);
    await adminPage.getByRole('menuitem', { name: /view details/i }).click();
    await expect(adminPage).toHaveURL(new RegExp(`/ca/certificates/${certs[0].serial}`));
  });

  test('refresh lists the certificates again', async ({ adminPage }) => {
    await adminPage.goto('/ca/certificates');
    await adminPage.waitForLoadState('networkidle');
    const again = adminPage.waitForResponse(isCertList);
    await adminPage.getByRole('button', { name: /refresh/i }).click();
    await again;
    await expect(adminPage.locator('table')).toBeVisible();
  });
});

test.describe('Issue Certificate, real server', () => {
  test('the dialog opens with the form fields, and Issue needs a subject', async ({ adminPage }) => {
    await adminPage.goto('/ca/certificates');
    await adminPage.getByRole('button', { name: /issue certificate/i }).first().click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.locator('h2', { hasText: /issue new certificate/i })).toBeVisible();
    for (const label of ['Subject', 'Certificate Type', 'Key Algorithm', 'Validity Period']) {
      await expect(adminPage.locator(`label:has-text("${label}")`)).toBeVisible();
    }
    await expect(dialog.getByRole('button', { name: /issue certificate/i })).toBeDisabled();
  });

  test('submitting the form issues a certificate the server then lists', async ({ adminPage, sdk }) => {
    const { commonName, res, alerts } = await issueThroughPage(adminPage);
    if (res.ok()) {
      await expect.poll(() => alerts.includes('Certificate issued successfully')).toBe(true);
      await expect.poll(async () => (await listCerts(sdk)).some((c) => c.commonName === commonName)).toBe(true);
    } else {
      // The console shows the server's refusal, and a refused issue adds nothing.
      const message = serverMessage(await res.json().catch(() => null));
      if (message) {
        await expect.poll(() => alerts.includes(`Failed to issue certificate: ${message}`)).toBe(true);
      } else {
        await expect.poll(() => alerts.some((a) => a.startsWith('Failed to issue certificate: '))).toBe(true);
      }
      expect((await listCerts(sdk)).some((c) => c.commonName === commonName)).toBe(false);
    }
  });
});

test.describe('Revoke Certificate, real server', () => {
  test('an active certificate offers Revoke, a revoked one does not', async ({ adminPage, sdk }) => {
    const certs = await listCerts(sdk);
    const active = certs.find(isValid);
    const revoked = certs.find(isRevoked);
    test.skip(!active && !revoked, 'the harness CA lists no active or revoked certificate');
    await adminPage.goto('/ca/certificates');
    if (active) {
      await openRowMenu(adminPage, active.commonName);
      await expect(adminPage.getByRole('menuitem', { name: /revoke/i })).toBeVisible();
      await adminPage.keyboard.press('Escape');
    }
    if (revoked) {
      await openRowMenu(adminPage, revoked.commonName);
      await expect(adminPage.getByRole('menuitem', { name: /revoke/i })).toHaveCount(0);
    }
  });

  test('revoking a certificate issued here leaves it revoked on the server', async ({ adminPage, sdk }) => {
    const { commonName, res, alerts } = await issueThroughPage(adminPage);
    test.skip(!res.ok(), 'the harness CA refused the issue');
    let serial = '';
    await expect
      .poll(async () => {
        serial = (await listCerts(sdk)).find((c) => c.commonName === commonName)?.serial ?? '';
        return serial;
      })
      .not.toBe('');
    await adminPage.goto('/ca/certificates');
    await openRowMenu(adminPage, commonName);
    const answer = adminPage.waitForResponse(
      (r) => r.request().method() === 'DELETE' && new URL(r.url()).pathname.startsWith(`${CERTS}/`)
    );
    await adminPage.getByRole('menuitem', { name: /revoke/i }).click();
    const confirm = adminPage.getByRole('alertdialog').or(adminPage.getByRole('dialog'));
    if (await confirm.count()) await confirm.getByRole('button', { name: /revoke|confirm/i }).last().click();
    const revoke = await answer;
    if (revoke.ok()) {
      await expect.poll(() => alerts.includes('Certificate revoked successfully')).toBe(true);
      await expect.poll(async () => (await crlSerials(sdk)).has(normSerial(serial))).toBe(true);
    } else {
      // The console shows the server's refusal, and the CRL lacks the serial.
      const message = serverMessage(await revoke.json().catch(() => null));
      if (message) {
        await expect.poll(() => alerts.includes(`Failed to revoke certificate: ${message}`)).toBe(true);
      } else {
        await expect.poll(() => alerts.some((a) => a.startsWith('Failed to revoke certificate: '))).toBe(true);
      }
      expect((await crlSerials(sdk)).has(normSerial(serial))).toBe(false);
    }
  });
});

test.describe('Certificate Details, real server', () => {
  test('the detail page shows the certificate, its downloads and Revoke by status', async ({ adminPage, sdk }) => {
    const certs = await listCerts(sdk);
    test.skip(certs.length === 0, 'the harness CA lists no certificate');
    const cert = certs[0];
    const res = await openDetail(adminPage, cert.serial);
    expect(res.ok()).toBe(true);
    await expect(adminPage.getByRole('heading', { name: /certificate details/i })).toBeVisible();
    await expect(adminPage.getByRole('heading', { name: cert.commonName })).toBeVisible();
    await expect(adminPage.getByRole('button', { name: /pem/i })).toBeVisible();
    await expect(adminPage.getByRole('button', { name: /der/i })).toBeVisible();
    const revoke = adminPage.getByRole('button', { name: /revoke/i });
    if (isRevoked(cert)) await expect(revoke).toHaveCount(0);
    else if (isValid(cert)) await expect(revoke).toBeVisible();

    await adminPage.getByRole('link', { name: /certificates/i }).first().click();
    await expect(adminPage).toHaveURL(/\/ca\/certificates\/?$/);
  });

  test('an unknown serial shows the server refusal', async ({ adminPage }) => {
    const res = await openDetail(adminPage, `e2e-absent-${Date.now()}`);
    expect(res.ok()).toBe(false);
    await expect(adminPage.getByRole('main').getByText(/error|not found/i).first()).toBeVisible();
  });
});

test.describe('Certificate Authority - Requests Page, real server', () => {
  test('the requests page loads its queue from the server', async ({ adminPage }) => {
    await adminPage.goto('/ca/requests');
    await expect(adminPage.getByRole('heading', { name: /certificate requests/i })).toBeVisible();
  });
});

test.describe('Certificate Authority - CRL Page, real server', () => {
  test('shows the coming-soon CRL page with its controls disabled', async ({ adminPage }) => {
    await adminPage.goto('/ca/crl');
    await expect(adminPage.getByRole('heading', { name: /certificate revocation list/i }).first()).toBeVisible();
    await expect(adminPage.getByText(/coming soon/i).first()).toBeVisible();
    await expect(adminPage.getByText(/last updated/i).first()).toBeVisible();
    await expect(adminPage.getByText(/next update/i).first()).toBeVisible();
    await expect(adminPage.getByText('Revoked Certificates:', { exact: true })).toBeVisible();
    await expect(adminPage.getByRole('heading', { name: /distribution points/i })).toBeVisible();
    await expect(adminPage.getByRole('button', { name: /generate crl/i })).toBeDisabled();
    await expect(adminPage.getByRole('button', { name: /download crl/i })).toBeDisabled();
  });
});

test.describe('Certificate Authority - Access Control, real server', () => {
  for (const path of ['/ca/certificates', '/ca/bundle']) {
    test(`redirects ${path} to login when signed out`, async ({ page }) => {
      await page.context().clearCookies();
      await page.goto(path);
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });
  }

  test('the signed-in admin gets Issue Certificate', async ({ adminPage }) => {
    await adminPage.goto('/ca/certificates');
    await expect(adminPage.getByRole('button', { name: /issue certificate/i }).first()).toBeVisible();
  });
});

test.describe('Certificate Authority - CA Bundle, real server', () => {
  test('shows the coming-soon bundle page with three disabled downloads', async ({ adminPage }) => {
    await adminPage.goto('/ca/bundle');
    await expect(adminPage.getByRole('heading', { name: 'CA Bundle', exact: true })).toBeVisible();
    await expect(adminPage.getByText('View and download certificate authority bundles and trust chains')).toBeVisible();
    await expect(adminPage.getByRole('heading', { name: 'Certificate Bundle Management' })).toBeVisible();
    await expect(adminPage.getByText('This feature is under development')).toBeVisible();
    await expect(adminPage.getByRole('heading', { name: 'Coming Soon' })).toBeVisible();
    await expect(adminPage.getByText(/in various formats \(PEM, DER, PKCS#7\)/)).toBeVisible();

    const sections: Array<[string, string]> = [
      ['Root CA Bundle', 'Download the root certificate authority bundle'],
      ['Intermediate Bundle', 'Download intermediate CA certificates'],
      ['Full Chain', 'Download the complete certificate chain'],
    ];
    for (const [heading, text] of sections) {
      await expect(adminPage.getByRole('heading', { name: heading })).toBeVisible();
      await expect(adminPage.getByText(text)).toBeVisible();
    }
    const downloads = adminPage.getByRole('button', { name: 'Download' });
    await expect(downloads).toHaveCount(3);
    for (let i = 0; i < 3; i++) await expect(downloads.nth(i)).toBeDisabled();
  });
});
