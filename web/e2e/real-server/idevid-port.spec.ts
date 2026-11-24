/**
 * TPM IDevID and IAK against the real-server harness (#2036, epic #1665).
 *
 * Ported from web/e2e/idevid.spec.ts. Each operation on /tpm/idevid is
 * driven from the page and held to what the server answers: the state is
 * read through sdk.idevid first, the request the page sent is read off the
 * wire, and the page must show the server's success or its failure. The
 * harness TPM decides which; canned values (manufacturer, flush count,
 * secret bytes) are gaps in docs/plans/1665-port-2.md.
 */
import { test, expect } from './fixtures';
import type { Page, Response } from '@playwright/test';
import { unwrapPayload, wireCount } from './fixtures/wire';

const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';

/** Waits for the page's method request to /api/v1/idevid<path> while action runs. */
async function serverCall(page: Page, method: string, path: string, action: () => Promise<void>): Promise<Response> {
  const [res] = await Promise.all([
    page.waitForResponse((r) => {
      const url = new URL(r.url());
      return r.request().method() === method && url.pathname.endsWith(`/v1/idevid${path}`);
    }),
    action(),
  ]);
  return res;
}

async function openPage(page: Page): Promise<void> {
  await page.goto('/tpm/idevid');
  await expect(page.getByRole('heading', { name: 'IDevID and IAK' })).toBeVisible();
}

async function confirm(page: Page, button: string): Promise<void> {
  await page.getByRole('button', { name: button, exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Confirm' }).click();
}

/** The page shows a failure when the server refused the call. */
async function expectFailureShown(page: Page): Promise<void> {
  await expect(page.getByText(/error|fail|refused|not/i).first()).toBeVisible();
}

test.describe('TPM IDevID and IAK', () => {
  test('HasIDevID shows the IDevID status the server reports', async ({ adminPage, sdk }) => {
    const res = await sdk.idevid.hasIDevID();
    await openPage(adminPage);
    if (res.success && res.data) {
      await expect(adminPage.getByTestId('idevid-status')).toHaveText(res.data.exists ? 'Present' : 'Absent');
    } else {
      await expect(adminPage.getByTestId('idevid-status')).not.toHaveText('Present');
    }
  });

  test('HasIAK shows the IAK status the server reports', async ({ adminPage, sdk }) => {
    const res = await sdk.idevid.hasIAK();
    await openPage(adminPage);
    if (res.success && res.data) {
      await expect(adminPage.getByTestId('iak-status')).toHaveText(res.data.exists ? 'Present' : 'Absent');
    } else {
      await expect(adminPage.getByTestId('iak-status')).not.toHaveText('Present');
    }
  });

  test('GetDeviceAttributes shows the device attributes the server reports', async ({ adminPage, sdk }) => {
    const res = await sdk.idevid.getDeviceAttributes();
    await openPage(adminPage);
    const attrs = adminPage.getByTestId('device-attributes');
    await expect(attrs).toBeVisible();
    if (res.success && res.data) {
      for (const value of Object.values(res.data.attributes ?? {})) {
        if (typeof value === 'string' && value.trim()) {
          await expect(attrs.getByText(value.trim()).first()).toBeVisible();
        }
      }
    }
  });

  test('GenerateIAK generates an IAK the server then reports', async ({ adminPage, sdk }) => {
    await openPage(adminPage);
    const res = await serverCall(adminPage, 'POST', '/iak/generate', () =>
      adminPage.getByRole('button', { name: 'Generate IAK' }).click(),
    );
    if (res.ok()) {
      const has = await sdk.idevid.hasIAK();
      expect(has.success).toBe(true);
      expect(has.data?.exists).toBe(true);
    } else {
      await expectFailureShown(adminPage);
    }
  });

  test('DeleteIAK sends nothing on cancel and shows the server answer on confirm', async ({ adminPage, sdk }) => {
    const deletes: string[] = [];
    adminPage.on('request', (req) => {
      if (req.method() === 'DELETE' && new URL(req.url()).pathname.endsWith('/v1/idevid/iak')) deletes.push(req.url());
    });
    await openPage(adminPage);

    await adminPage.getByRole('button', { name: 'Delete IAK', exact: true }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText('does not evict it');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    expect(deletes).toHaveLength(0);

    const before = await sdk.idevid.hasIAK();
    const res = await serverCall(adminPage, 'DELETE', '/iak', () => confirm(adminPage, 'Delete IAK'));
    if (res.ok()) {
      await expect(adminPage.getByText('Error deleting IAK')).toHaveCount(0);
    } else {
      await expect(adminPage.getByText('Error deleting IAK').first()).toBeVisible();
      // A refused delete leaves the IAK as it was.
      const after = await sdk.idevid.hasIAK();
      expect(after.data?.exists).toBe(before.data?.exists);
    }
  });

  test('CreateIAKCSR shows the CSR the server returns', async ({ adminPage }) => {
    await openPage(adminPage);
    const res = await serverCall(adminPage, 'POST', '/iak/csr', () =>
      adminPage.getByRole('button', { name: 'Create IAK CSR' }).click(),
    );
    if (res.ok()) {
      await expect(adminPage.getByTestId('idevid-result').locator('pre')).not.toBeEmpty();
    } else {
      await expectFailureShown(adminPage);
    }
  });

  test('CreateLDevID sends the common name and shows the server answer', async ({ adminPage }) => {
    const cn = `node-${Date.now().toString(36)}`;
    await openPage(adminPage);
    await adminPage.getByLabel('LDevID common name').fill(cn);
    const res = await serverCall(adminPage, 'POST', '/ldevid', () =>
      adminPage.getByRole('button', { name: 'Create LDevID' }).click(),
    );
    expect(res.request().postDataJSON()).toEqual({ template: { commonName: cn } });
    if (res.ok()) {
      await expect(adminPage.getByTestId('idevid-result')).not.toBeEmpty();
    } else {
      await expectFailureShown(adminPage);
    }
  });

  test('InstallIDevIDCertificate sends the PEM and shows the server answer', async ({ adminPage }) => {
    await openPage(adminPage);
    await adminPage.getByLabel('IDevID certificate (PEM)').fill(PEM);
    const res = await serverCall(adminPage, 'POST', '/certificate', () =>
      adminPage.getByRole('button', { name: 'Install IDevID certificate' }).click(),
    );
    const sent = (res.request().postDataJSON() as { certificatePem: string }).certificatePem;
    expect(Buffer.from(sent, 'base64').toString()).toBe(PEM);
    // The PEM is not a certificate: the server must refuse it, and the page say so.
    expect(res.ok()).toBe(false);
    await expectFailureShown(adminPage);
  });

  test('InstallIAKCertificate sends the PEM and shows the server answer', async ({ adminPage }) => {
    await openPage(adminPage);
    await adminPage.getByLabel('IAK certificate (PEM)').fill(PEM);
    const res = await serverCall(adminPage, 'POST', '/iak/certificate', () =>
      adminPage.getByRole('button', { name: 'Install IAK certificate' }).click(),
    );
    expect(res.ok()).toBe(false);
    await expectFailureShown(adminPage);
  });

  test('DeleteIAKCertificate deletes after confirmation and shows the server answer', async ({ adminPage, sdk }) => {
    await openPage(adminPage);
    const res = await serverCall(adminPage, 'DELETE', '/iak/certificate', () =>
      confirm(adminPage, 'Delete IAK certificate'),
    );
    if (res.ok()) {
      const cert = await sdk.idevid.getIAKCertificate();
      expect(cert.success && !!cert.data).toBe(false);
    } else {
      await expectFailureShown(adminPage);
    }
  });

  test('FlushTransientContexts shows the count the server flushed', async ({ adminPage }) => {
    await openPage(adminPage);
    const res = await serverCall(adminPage, 'POST', '/flush', () => confirm(adminPage, 'Flush transient contexts'));
    if (res.ok()) {
      const body = unwrapPayload<{ flushedCount?: unknown; flushed_count?: unknown }>(await res.json());
      const count = wireCount(body.flushedCount ?? body.flushed_count ?? 0);
      await expect(adminPage.getByTestId('idevid-result')).toContainText(`Flushed ${count}`);
    } else {
      await expectFailureShown(adminPage);
    }
  });

  test('ActivateCredential sends the blob and secret and shows the server answer', async ({ adminPage }) => {
    await openPage(adminPage);
    await adminPage.getByLabel('Credential blob (base64)').fill('QkxPQg==');
    await adminPage.getByLabel('Encrypted secret (base64)').fill('U0VD');
    const res = await serverCall(adminPage, 'POST', '/activate-credential', () =>
      adminPage.getByRole('button', { name: 'Activate credential' }).click(),
    );
    expect(res.request().postDataJSON()).toEqual({ credentialBlob: 'QkxPQg==', secret: 'U0VD' });
    // The blob was not made for this TPM's EK: the server cannot activate it.
    expect(res.ok()).toBe(false);
    await expectFailureShown(adminPage);
  });
});
