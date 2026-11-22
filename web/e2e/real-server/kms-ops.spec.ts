/**
 * KMS operations page against the real-server harness (#2036, epic #1665;
 * #1734, slice 20 of #1665): one test per REST operation.
 *
 * Ported from web/e2e/kms-ops.spec.ts. Each test that needs a key generates
 * its own through sdk.kms.generateKey (a unique name) and deletes it after.
 * The request the page sent is read off the wire and the page is held to the
 * server's answer: digests, HMACs and versions are checked against what the
 * server (or a local hash of the same input) returns, not canned bytes.
 * /kms/operations is not the /kms keys page that kms-port.spec.ts covers.
 */
import { createHash } from 'node:crypto';
import { test, expect } from './fixtures';
import type { Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';

type Algorithm = 'AES_256' | 'HMAC_SHA256';
type Usage = 'ENCRYPT' | 'DECRYPT' | 'WRAP' | 'UNWRAP' | 'HMAC';

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

function uniqueName(tag: string): string {
  return `e2e-ops-${tag}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

/** Generates a key named name; returns the id the server gave it. */
async function seedKey(sdk: PlatformClient, name: string, algorithm: Algorithm, usage: Usage[]): Promise<string> {
  const res = await sdk.kms.generateKey({ name, keySpec: { algorithm, usage } });
  const err: unknown = res.error;
  if (!res.success || !res.data) throw new Error(`[real-server] kms.generateKey(${name}): ${JSON.stringify(err)}`);
  return res.data.key?.keyId ?? name;
}

async function dropKey(sdk: PlatformClient, keyId: string): Promise<void> {
  await sdk.kms.deleteKey({ keyId, force: true });
}

async function openPage(page: Page): Promise<void> {
  await page.goto('/kms/operations');
  await expect(page.getByRole('heading', { name: 'KMS Operations' })).toBeVisible();
}

/** Waits for the page's method request whose path ends with suffix while action runs. */
async function serverCall(page: Page, method: string, suffix: string, action: () => Promise<void>): Promise<Response> {
  const [res] = await Promise.all([
    page.waitForResponse(
      (r) => r.request().method() === method && new URL(r.url()).pathname.replace(/\/$/, '').endsWith(suffix),
    ),
    action(),
  ]);
  return res;
}

test.describe('KMS operations', () => {
  test('imports a key', async ({ adminPage, sdk }) => {
    const name = uniqueName('import');
    const material = Buffer.alloc(32, 7).toString('base64');
    try {
      await openPage(adminPage);
      const card = adminPage.getByTestId('op-import');
      await card.getByLabel('Key name').fill(name);
      await card.getByLabel('Algorithm').fill('aes-256-gcm');
      await card.getByLabel('Key material (base64)').fill(material);
      const res = await serverCall(adminPage, 'POST', '/keys/import', () =>
        card.getByRole('button', { name: 'Import' }).click(),
      );
      expect(res.request().postDataJSON()).toMatchObject({ name, key_material: material });
      if (res.ok()) {
        await expect(adminPage.getByTestId('import-result')).toContainText(`Imported ${name}`);
      } else {
        await expect(adminPage.getByTestId('kms-ops-error')).toBeVisible();
      }
    } finally {
      await dropKey(sdk, name);
    }
  });

  async function askStatusChange(page: Page, keyId: string) {
    const card = page.getByTestId('op-status');
    await card.getByLabel('Key name').fill(keyId);
    await card.getByLabel('New status').selectOption('DISABLED');
    await card.getByLabel('Version').fill('1');
    await card.getByRole('button', { name: 'Update status' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText(`Set ${keyId} to DISABLED?`);
    return dialog;
  }

  test('updates key status after the confirm dialog is accepted', async ({ adminPage, sdk }) => {
    const keyId = await seedKey(sdk, uniqueName('status'), 'AES_256', ['ENCRYPT', 'DECRYPT']);
    try {
      await openPage(adminPage);
      const dialog = await askStatusChange(adminPage, keyId);
      const res = await serverCall(adminPage, 'PUT', `/keys/${encodeURIComponent(keyId)}/status`, () =>
        dialog.getByRole('button', { name: 'Confirm' }).click(),
      );
      expect(res.request().postDataJSON()).toEqual({ status: 'DISABLED', version: 1 });
      if (res.ok()) {
        await expect(adminPage.getByTestId('status-result')).toHaveText(`${keyId} v1 is DISABLED`);
      } else {
        await expect(adminPage.getByTestId('kms-ops-error')).toBeVisible();
      }
    } finally {
      await dropKey(sdk, keyId);
    }
  });

  test('sends no status change when the confirm dialog is cancelled', async ({ adminPage, sdk }) => {
    const keyId = await seedKey(sdk, uniqueName('cancel'), 'AES_256', ['ENCRYPT', 'DECRYPT']);
    const puts: string[] = [];
    adminPage.on('request', (req) => {
      if (req.method() === 'PUT' && /\/status\/?$/.test(new URL(req.url()).pathname)) puts.push(req.url());
    });
    try {
      await openPage(adminPage);
      const dialog = await askStatusChange(adminPage, keyId);
      await dialog.getByRole('button', { name: 'Cancel' }).click();
      await expect(dialog).toBeHidden();
      await expect(adminPage.getByTestId('status-result')).toHaveCount(0);
      expect(puts).toHaveLength(0);
    } finally {
      await dropKey(sdk, keyId);
    }
  });

  test('lists key versions', async ({ adminPage, sdk }) => {
    const keyId = await seedKey(sdk, uniqueName('versions'), 'AES_256', ['ENCRYPT', 'DECRYPT']);
    try {
      const versions = await sdk.kms.getKeyVersions({ keyId });
      await openPage(adminPage);
      const card = adminPage.getByTestId('op-versions');
      await card.getByLabel('Key name').fill(keyId);
      const res = await serverCall(adminPage, 'GET', `/keys/${encodeURIComponent(keyId)}/versions`, () =>
        card.getByRole('button', { name: 'List versions' }).click(),
      );
      if (res.ok() && versions.success) {
        for (const v of versions.data?.versions ?? []) {
          await expect(adminPage.getByTestId('versions-result')).toContainText(`v${v.version}`);
        }
      } else {
        await expect(adminPage.getByTestId('kms-ops-error')).toBeVisible();
      }
    } finally {
      await dropKey(sdk, keyId);
    }
  });

  test('hashes data', async ({ adminPage }) => {
    await openPage(adminPage);
    const card = adminPage.getByTestId('op-hash');
    await card.getByLabel('Data', { exact: true }).fill('hello');
    await card.getByLabel('Hash algorithm').fill('SHA384');
    const res = await serverCall(adminPage, 'POST', '/hash', () => card.getByRole('button', { name: 'Hash' }).click());
    expect(res.request().postDataJSON()).toEqual({ data: b64('hello'), hash: 'SHA384' });
    expect(res.ok()).toBe(true);
    const digest = createHash('sha384').update('hello').digest('base64');
    await expect(adminPage.getByTestId('hash-result')).toHaveText(`SHA384: ${digest}`);
  });

  test('computes an HMAC', async ({ adminPage, sdk }) => {
    const keyId = await seedKey(sdk, uniqueName('mac'), 'HMAC_SHA256', ['HMAC']);
    try {
      const expected = await sdk.kms.hmac({ keyId, message: b64('hello'), hashAlgorithm: 'SHA256' });
      await openPage(adminPage);
      const card = adminPage.getByTestId('op-hmac');
      await card.getByLabel('Key name').fill(keyId);
      await card.getByLabel('Data', { exact: true }).fill('hello');
      const res = await serverCall(adminPage, 'POST', `/hmac/${encodeURIComponent(keyId)}`, () =>
        card.getByRole('button', { name: 'Compute HMAC' }).click(),
      );
      expect(res.request().postDataJSON()).toEqual({ data: b64('hello'), hash: 'SHA256' });
      if (res.ok() && expected.success && expected.data) {
        // HMAC is deterministic: the page shows what the SDK got for the same input.
        await expect(adminPage.getByTestId('hmac-result')).toHaveText(expected.data.hmac);
      } else {
        await expect(adminPage.getByTestId('kms-ops-error')).toBeVisible();
      }
    } finally {
      await dropKey(sdk, keyId);
    }
  });

  test('verifies an HMAC', async ({ adminPage, sdk }) => {
    const keyId = await seedKey(sdk, uniqueName('verify'), 'HMAC_SHA256', ['HMAC']);
    try {
      await openPage(adminPage);
      const card = adminPage.getByTestId('op-verify-hmac');
      await card.getByLabel('Key name').fill(keyId);
      await card.getByLabel('Data', { exact: true }).fill('hello');
      await card.getByLabel('HMAC (base64)').fill(b64('bad'));
      await card.getByLabel('Hash algorithm').fill('SHA512');
      const res = await serverCall(adminPage, 'POST', `/hmac/${encodeURIComponent(keyId)}/verify`, () =>
        card.getByRole('button', { name: 'Verify HMAC' }).click(),
      );
      expect(res.request().postDataJSON()).toEqual({ data: b64('hello'), hmac: b64('bad'), hash: 'SHA512' });
      if (res.ok()) {
        // A made-up MAC never verifies.
        await expect(adminPage.getByTestId('verify-hmac-result')).toHaveText('HMAC invalid');
      } else {
        await expect(adminPage.getByTestId('kms-ops-error')).toBeVisible();
      }
    } finally {
      await dropKey(sdk, keyId);
    }
  });

  test('generates random bytes', async ({ adminPage }) => {
    await openPage(adminPage);
    const card = adminPage.getByTestId('op-random');
    await card.getByLabel('Number of bytes').fill('4');
    const res = await serverCall(adminPage, 'POST', '/random', () =>
      card.getByRole('button', { name: 'Generate random' }).click(),
    );
    expect(res.request().postDataJSON()).toEqual({ num_bytes: 4 });
    expect(res.ok()).toBe(true);
    const result = adminPage.getByTestId('random-result');
    await expect(result).not.toBeEmpty();
    expect(Buffer.from((await result.textContent())?.trim() ?? '', 'base64')).toHaveLength(4);
  });

  test('generates a data key', async ({ adminPage, sdk }) => {
    const kek = await seedKey(sdk, uniqueName('kek'), 'AES_256', ['ENCRYPT', 'DECRYPT']);
    try {
      await openPage(adminPage);
      const card = adminPage.getByTestId('op-data-key');
      await card.getByLabel('Key name').fill(kek);
      await card.getByLabel('Key size').fill('128');
      const res = await serverCall(adminPage, 'POST', '/data-keys', () =>
        card.getByRole('button', { name: 'Generate data key' }).click(),
      );
      expect(res.request().postDataJSON()).toEqual({ key_id: kek, algorithm: 'AES', key_size: 128 });
      if (res.ok()) {
        const result = adminPage.getByTestId('data-key-result');
        await expect(result).toContainText('plaintext: ');
        await expect(result).toContainText('encrypted: ');
      } else {
        await expect(adminPage.getByTestId('kms-ops-error')).toBeVisible();
      }
    } finally {
      await dropKey(sdk, kek);
    }
  });

  test('generates a wrapped data key', async ({ adminPage, sdk }) => {
    const kek = await seedKey(sdk, uniqueName('wrap'), 'AES_256', ['WRAP', 'UNWRAP', 'ENCRYPT', 'DECRYPT']);
    try {
      await openPage(adminPage);
      const card = adminPage.getByTestId('op-wrapped-data-key');
      await card.getByLabel('Wrapping key name').fill(kek);
      const res = await serverCall(adminPage, 'POST', '/data-keys/wrapped', () =>
        card.getByRole('button', { name: 'Generate wrapped data key' }).click(),
      );
      expect(res.request().postDataJSON()).toEqual({ wrapping_key_id: kek, key_algorithm: 'AES', key_size: 256 });
      if (res.ok()) {
        await expect(adminPage.getByTestId('wrapped-data-key-result')).toContainText(`wrapped by ${kek}: `);
      } else {
        await expect(adminPage.getByTestId('kms-ops-error')).toBeVisible();
      }
    } finally {
      await dropKey(sdk, kek);
    }
  });

  test('shows backend status', async ({ adminPage, sdk }) => {
    const status = await sdk.kms.getBackendStatus();
    await openPage(adminPage);
    await adminPage.getByTestId('op-backend').getByRole('button', { name: 'Check backend' }).click();
    if (status.success && status.data) {
      await expect(adminPage.getByTestId('backend-result')).toContainText(status.data.backend_type);
    } else {
      await expect(adminPage.getByTestId('kms-ops-error')).toBeVisible();
    }
  });

  test('shows the error of a failed operation', async ({ adminPage }) => {
    // An HMAC under a key the server does not hold fails for real.
    const missing = uniqueName('missing');
    await openPage(adminPage);
    const card = adminPage.getByTestId('op-hmac');
    await card.getByLabel('Key name').fill(missing);
    await card.getByLabel('Data', { exact: true }).fill('hello');
    const res = await serverCall(adminPage, 'POST', `/hmac/${missing}`, () =>
      card.getByRole('button', { name: 'Compute HMAC' }).click(),
    );
    expect(res.ok()).toBe(false);
    await expect(adminPage.getByTestId('kms-ops-error')).toBeVisible();
    await expect(adminPage.getByTestId('hmac-result')).toHaveCount(0);
  });
});
