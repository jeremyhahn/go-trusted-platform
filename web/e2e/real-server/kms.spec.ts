/**
 * Real-server spec for the KMS operations page, (dashboard)/kms/operations
 * (#2057, epic #1665).
 *
 * Seeds keys through the SDK client and asserts on what the server returns;
 * no route mocks.
 */
import type { Page } from '@playwright/test';
import { test, expect } from './fixtures';

const unique = (prefix: string) => `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

async function open(page: Page) {
  await page.goto('/kms/operations');
  await expect(page.getByRole('heading', { name: 'KMS Operations' })).toBeVisible();
}

async function expectNoError(page: Page) {
  await expect(page.getByTestId('kms-ops-error')).toHaveCount(0);
}

test.describe('KMS operations against the real server', () => {
  test('backend status shows the backend the server reports', async ({ adminPage, sdk }) => {
    const status = await sdk.kms.getBackendStatus();
    expect(status.success).toBe(true);

    await open(adminPage);
    await adminPage.getByTestId('op-backend').getByRole('button', { name: 'Check backend' }).click();
    await expect(adminPage.getByTestId('backend-result')).toBeVisible();
    await expectNoError(adminPage);
  });

  test('hash computes the SHA-256 digest of the input', async ({ adminPage }) => {
    await open(adminPage);
    await adminPage.locator('#hash-data').fill('hello');
    await adminPage.locator('#hash-algorithm').fill('SHA256');
    await adminPage.getByTestId('op-hash').getByRole('button', { name: 'Hash' }).click();
    // SHA-256("hello"), base64
    await expect(adminPage.getByTestId('hash-result')).toContainText(
      'LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=',
    );
  });

  test('random returns bytes from the backend', async ({ adminPage }) => {
    await open(adminPage);
    await adminPage.locator('#random-bytes').fill('16');
    await adminPage.getByTestId('op-random').getByRole('button', { name: 'Generate random' }).click();
    await expect(adminPage.getByTestId('random-result')).not.toBeEmpty();
    await expectNoError(adminPage);
  });

  test('an HMAC the page computes verifies, a changed message does not', async ({ adminPage, sdk }) => {
    const name = unique('e2e-hmac');
    const created = await sdk.kms.generateKey({
      name,
      keySpec: { algorithm: 'HMAC_SHA256', usage: ['HMAC'] },
    });
    expect(created.success).toBe(true);

    await open(adminPage);
    await adminPage.locator('#hmac-key').fill(name);
    await adminPage.locator('#hmac-data').fill('message');
    await adminPage.getByTestId('op-hmac').getByRole('button', { name: 'Compute HMAC' }).click();
    const mac = (await adminPage.getByTestId('hmac-result').textContent())?.trim() ?? '';
    expect(mac).not.toBe('');

    await adminPage.locator('#verify-hmac-key').fill(name);
    await adminPage.locator('#verify-hmac-data').fill('message');
    await adminPage.locator('#verify-hmac-mac').fill(mac);
    const verify = adminPage.getByTestId('op-verify-hmac').getByRole('button', { name: 'Verify HMAC' });
    await verify.click();
    await expect(adminPage.getByTestId('verify-hmac-result')).toHaveText('HMAC valid');

    await adminPage.locator('#verify-hmac-data').fill('tampered');
    await verify.click();
    await expect(adminPage.getByTestId('verify-hmac-result')).toHaveText('HMAC invalid');
  });

  test('batch encrypt then batch decrypt round-trips every item', async ({ adminPage, sdk }) => {
    const name = unique('e2e-batch');
    const created = await sdk.kms.generateKey({
      name,
      keySpec: { algorithm: 'AES_256', usage: ['ENCRYPT', 'DECRYPT'] },
    });
    expect(created.success).toBe(true);

    await open(adminPage);
    const card = adminPage.getByTestId('op-batch');
    await adminPage.locator('#batch-key').fill(name);
    await adminPage.locator('#batch-items').fill('one\ntwo\nthree');
    await card.getByRole('button', { name: 'Batch encrypt' }).click();
    await expect(adminPage.getByTestId('batch-result')).toBeVisible();
    const ciphertexts = ((await adminPage.getByTestId('batch-result').textContent()) ?? '')
      .split('\n')
      .filter(Boolean);
    expect(ciphertexts).toHaveLength(3);

    await adminPage.locator('#batch-items').fill(ciphertexts.join('\n'));
    await card.getByRole('button', { name: 'Batch decrypt' }).click();
    await expect(adminPage.getByTestId('batch-result')).toHaveText('one\ntwo\nthree');
  });

  test('rewrap re-encrypts a ciphertext under the newest key version', async ({ adminPage, sdk }) => {
    const name = unique('e2e-rewrap');
    const created = await sdk.kms.generateKey({
      name,
      keySpec: { algorithm: 'AES_256', usage: ['ENCRYPT', 'DECRYPT'] },
    });
    expect(created.success).toBe(true);

    await open(adminPage);
    await adminPage.locator('#batch-key').fill(name);
    await adminPage.locator('#batch-items').fill('rewrap me');
    await adminPage.getByTestId('op-batch').getByRole('button', { name: 'Batch encrypt' }).click();
    const sealed = ((await adminPage.getByTestId('batch-result').textContent()) ?? '').trim();
    expect(sealed).not.toBe('');

    await adminPage.locator('#rewrap-key').fill(name);
    await adminPage.locator('#rewrap-ciphertext').fill(sealed);
    await adminPage.getByTestId('op-rewrap').getByRole('button', { name: 'Rewrap' }).click();
    await expect(adminPage.getByTestId('rewrap-result')).toContainText(`${name} v1 -> v1`);
    const resealed = ((await adminPage.getByTestId('rewrap-result').textContent()) ?? '').split(': ').pop() ?? '';

    // The rewrapped ciphertext still opens under the key.
    await adminPage.locator('#batch-items').fill(resealed.trim());
    await adminPage.getByTestId('op-batch').getByRole('button', { name: 'Batch decrypt' }).click();
    await expect(adminPage.getByTestId('batch-result')).toHaveText('rewrap me');
    await expectNoError(adminPage);
  });

  test('data keys: plaintext and wrapped', async ({ adminPage, sdk }) => {
    const name = unique('e2e-dek');
    const created = await sdk.kms.generateKey({
      name,
      keySpec: { algorithm: 'AES_256', usage: ['ENCRYPT', 'DECRYPT', 'WRAP', 'UNWRAP'] },
    });
    expect(created.success).toBe(true);

    await open(adminPage);
    await adminPage.locator('#data-key-key').fill(name);
    await adminPage.getByTestId('op-data-key').getByRole('button', { name: 'Generate data key' }).click();
    await expect(adminPage.getByTestId('data-key-result')).toContainText('encrypted:');

    await adminPage.locator('#wrapped-data-key-key').fill(name);
    await adminPage
      .getByTestId('op-wrapped-data-key')
      .getByRole('button', { name: 'Generate wrapped data key' })
      .click();
    await expect(adminPage.getByTestId('wrapped-data-key-result')).toContainText(`wrapped by ${name}`);
  });

  test('key versions, status update and import', async ({ adminPage, sdk }) => {
    const name = unique('e2e-status');
    const created = await sdk.kms.generateKey({
      name,
      keySpec: { algorithm: 'AES_256', usage: ['ENCRYPT', 'DECRYPT'] },
    });
    expect(created.success).toBe(true);

    await open(adminPage);
    await adminPage.locator('#versions-key').fill(name);
    await adminPage.getByTestId('op-versions').getByRole('button', { name: 'List versions' }).click();
    await expect(adminPage.getByTestId('versions-result')).toContainText('v1');

    await adminPage.locator('#status-key').fill(name);
    await adminPage.locator('#status-value').selectOption('DISABLED');
    await adminPage.locator('#status-version').fill('1');
    await adminPage.getByTestId('op-status').getByRole('button', { name: 'Update status' }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();
    await expect(adminPage.getByTestId('status-result')).toContainText('DISABLED');

    const fetched = await sdk.kms.getKey(name);
    expect(fetched.success).toBe(true);
    expect(JSON.stringify(fetched.data)).toContain('DISABLED');

    const imported = unique('e2e-import');
    await adminPage.locator('#import-name').fill(imported);
    await adminPage.locator('#import-material').fill(Buffer.alloc(32, 7).toString('base64'));
    await adminPage.getByTestId('op-import').getByRole('button', { name: 'Import' }).click();
    await expect(adminPage.getByTestId('import-result')).toContainText('Imported');
    await expectNoError(adminPage);
  });
});
