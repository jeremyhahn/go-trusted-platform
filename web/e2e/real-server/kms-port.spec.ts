/**
 * KMS page against the real-server harness (#2036, epic #1665).
 *
 * Ported from web/e2e/kms.spec.ts. Keys are generated through the SDK and
 * every assertion reads what the server returned. Mocked cases with no server
 * behaviour behind them (injected 500s, artificial latency, a member session,
 * the skipped encryption-operations block) are listed as gaps in the PR body.
 */
import type { Page } from '@playwright/test';
import { test, expect } from './fixtures';

interface KeyHandle {
  keyId: string;
  version: number;
  algorithm: string;
  status: string;
}

interface Result<T> {
  success: boolean;
  data?: T;
  error?: unknown;
}

/** The part of the SDK's KMSService these specs drive. */
interface KmsSdk {
  kms: {
    generateKey(req: {
      name: string;
      keySpec: { algorithm: string; usage: string[] };
    }): Promise<Result<{ key?: KeyHandle }>>;
    getKey(keyId: string): Promise<Result<{ key: KeyHandle }>>;
    listKeys(): Promise<Result<{ keys: KeyHandle[] }>>;
  };
}

/** A key name unique to one test run, so parallel workers never collide. */
function keyName(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6).toString(36)}`;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Matches a key by the name it was generated with or the ID the server gave it. */
function keyText(name: string, key: KeyHandle): RegExp {
  return new RegExp(`${escapeRe(name)}|${escapeRe(key.keyId)}`, 'i');
}

/** Generates a key through the SDK and returns the handle the server answered with. */
async function generate(sdk: KmsSdk, name: string, algorithm = 'AES_256'): Promise<KeyHandle> {
  const usage = algorithm.startsWith('AES') ? ['ENCRYPT', 'DECRYPT'] : ['SIGN', 'VERIFY'];
  const res = await sdk.kms.generateKey({ name, keySpec: { algorithm, usage } });
  expect(res.success, JSON.stringify(res.error)).toBe(true);
  const key = res.data?.key;
  expect(key?.keyId).toBeTruthy();
  return key as KeyHandle;
}

/** Reads a key back from the server; null when the server no longer has it. */
async function fetchKey(sdk: KmsSdk, keyId: string): Promise<KeyHandle | null> {
  const res = await sdk.kms.getKey(keyId);
  return res.success && res.data ? res.data.key : null;
}

function keyRow(page: Page, name: string, key: KeyHandle) {
  return page.locator('tr').filter({ hasText: keyText(name, key) });
}

async function openRowMenu(page: Page, name: string, key: KeyHandle): Promise<void> {
  await keyRow(page, name, key).locator('button').filter({ has: page.locator('svg') }).last().click();
}

test.describe('KMS (Key Management System)', () => {
  test.describe('Key List', () => {
    test('shows the key table with the keys the server holds', async ({ adminPage, sdk }) => {
      const aesName = keyName('production-key');
      const rsaName = keyName('signing-key');
      const aes = await generate(sdk, aesName, 'AES_256');
      const rsa = await generate(sdk, rsaName, 'RSA_4096');

      await adminPage.goto('/kms');

      await expect(adminPage.getByRole('heading', { name: /cryptographic keys/i })).toBeVisible();
      await expect(adminPage.getByRole('columnheader', { name: /name/i })).toBeVisible();
      await expect(adminPage.getByRole('columnheader', { name: /algorithm/i })).toBeVisible();
      await expect(adminPage.getByRole('columnheader', { name: /type/i })).toBeVisible();
      await expect(adminPage.getByRole('columnheader', { name: /status/i })).toBeVisible();
      await expect(keyRow(adminPage, aesName, aes)).toBeVisible();
      await expect(keyRow(adminPage, rsaName, rsa)).toBeVisible();
    });

    test('shows an active badge for an enabled key', async ({ adminPage, sdk }) => {
      const name = keyName('active-key');
      const key = await generate(sdk, name);
      expect(key.status).toBe('ENABLED');

      await adminPage.goto('/kms');

      const row = keyRow(adminPage, name, key);
      await expect(row).toBeVisible();
      await expect(row.getByText(/active/i)).toBeVisible();
    });

    test('shows one row per algorithm the server generated', async ({ adminPage, sdk }) => {
      const seeded: Array<[string, KeyHandle]> = [];
      for (const [prefix, algorithm] of [
        ['aes-key', 'AES_256'],
        ['rsa-key', 'RSA_4096'],
        ['ecdsa-key', 'ECDSA_P256'],
      ]) {
        const name = keyName(prefix);
        seeded.push([name, await generate(sdk, name, algorithm)]);
      }

      await adminPage.goto('/kms');

      for (const [name, key] of seeded) {
        await expect(keyRow(adminPage, name, key)).toBeVisible();
      }
    });

    test('filters keys by search query', async ({ adminPage, sdk }) => {
      const wantedName = keyName('production-encryption-key');
      const otherName = keyName('development-signing-key');
      const wanted = await generate(sdk, wantedName);
      const other = await generate(sdk, otherName);

      await adminPage.goto('/kms');
      await expect(keyRow(adminPage, wantedName, wanted)).toBeVisible();

      await adminPage.fill('input[placeholder*="Search"]', wantedName);

      await expect(keyRow(adminPage, wantedName, wanted)).toBeVisible();
      await expect(keyRow(adminPage, otherName, other)).toHaveCount(0);
    });
  });

  test.describe('Key Details', () => {
    test('opens key details from the list', async ({ adminPage, sdk }) => {
      const name = keyName('test-key');
      const key = await generate(sdk, name);

      await adminPage.goto('/kms');
      await openRowMenu(adminPage, name, key);
      await adminPage.getByRole('menuitem', { name: /view details/i }).click();

      await expect(adminPage).toHaveURL(new RegExp(`/kms/${escapeRe(encodeURIComponent(key.keyId))}`));
      await expect(adminPage.getByRole('heading', { name: keyText(name, key) })).toBeVisible();
    });

    test('shows the metadata the server returns', async ({ adminPage, sdk }) => {
      const name = keyName('production-encryption-key');
      const key = await generate(sdk, name, 'AES_256');

      await adminPage.goto(`/kms/${encodeURIComponent(key.keyId)}`);

      await expect(adminPage.getByRole('heading', { name: keyText(name, key) })).toBeVisible();
      await expect(adminPage.getByText(key.algorithm).first()).toBeVisible();
    });

    test('shows key not found for an unknown key', async ({ adminPage, sdk }) => {
      const missing = keyName('nonexistent-key');
      expect(await fetchKey(sdk, missing)).toBeNull();

      await adminPage.goto(`/kms/${missing}`);

      await expect(adminPage.getByText(/key not found|error loading key/i).first()).toBeVisible();
      await expect(adminPage.getByRole('button', { name: /back to keys/i })).toBeVisible();
    });

    test('navigates back to the keys list', async ({ adminPage, sdk }) => {
      const name = keyName('nav-test-key');
      const key = await generate(sdk, name);

      await adminPage.goto(`/kms/${encodeURIComponent(key.keyId)}`);
      const heading = adminPage.getByRole('heading', { name: keyText(name, key) });
      await expect(heading).toBeVisible();

      await heading.locator('..').locator('..').locator('button').first().click();

      await expect(adminPage).toHaveURL(/\/kms\/?$/, { timeout: 10000 });
    });
  });

  test.describe('Key CRUD Operations', () => {
    test('opens the generate key dialog', async ({ adminPage }) => {
      await adminPage.goto('/kms');

      await adminPage.getByRole('button', { name: /generate key/i }).click();

      const dialog = adminPage.getByRole('dialog');
      await expect(dialog).toBeVisible();
      await expect(dialog.locator('h2, h3').filter({ hasText: /generate.*key/i }).first()).toBeVisible();
    });

    test('generates a key the server then lists', async ({ adminPage, sdk }) => {
      const name = keyName('New-Encryption-Key');

      await adminPage.goto('/kms');
      await adminPage.getByRole('button', { name: /generate key/i }).click();
      await adminPage.locator('input#name').fill(name);
      await adminPage.getByRole('button', { name: /generate/i }).last().click();

      await expect(adminPage.getByText(/key generated|generated successfully/i).first()).toBeVisible();
      const listed = await sdk.kms.listKeys();
      expect(listed.success).toBe(true);
      expect(JSON.stringify(listed.data?.keys ?? [])).toContain(name);
    });

    test('rotates a key and the server bumps its version', async ({ adminPage, sdk }) => {
      const name = keyName('rotate-me');
      const key = await generate(sdk, name);

      await adminPage.goto('/kms');
      adminPage.on('dialog', (dialog) => dialog.accept());
      await openRowMenu(adminPage, name, key);
      await adminPage.getByRole('menuitem', { name: /rotate/i }).click();

      await expect(adminPage.getByText(/key rotated|rotated successfully/i).first()).toBeVisible();
      const after = await fetchKey(sdk, key.keyId);
      expect(after?.version ?? 0).toBeGreaterThan(key.version);
    });

    test('deletes a key after confirmation', async ({ adminPage, sdk }) => {
      const name = keyName('delete-me');
      const key = await generate(sdk, name);

      await adminPage.goto('/kms');
      await expect(keyRow(adminPage, name, key)).toBeVisible();
      adminPage.on('dialog', (dialog) => dialog.accept());
      await openRowMenu(adminPage, name, key);
      await adminPage.getByRole('menuitem', { name: /delete/i }).click();

      await expect(adminPage.getByText(/key deleted|deleted successfully/i).first()).toBeVisible();
      const after = await fetchKey(sdk, key.keyId);
      expect(after === null || after.status === 'PENDING_DELETION').toBe(true);
    });

    test('keeps the key when the delete dialog is dismissed', async ({ adminPage, sdk }) => {
      const name = keyName('keep-me');
      const key = await generate(sdk, name);

      await adminPage.goto('/kms');
      adminPage.on('dialog', (dialog) => dialog.dismiss());
      await openRowMenu(adminPage, name, key);
      await adminPage.getByRole('menuitem', { name: /delete/i }).click();

      await expect(keyRow(adminPage, name, key)).toBeVisible();
      expect((await fetchKey(sdk, key.keyId))?.status).toBe('ENABLED');
    });

    test('rotates a key from its details page', async ({ adminPage, sdk }) => {
      const name = keyName('details-rotate-key');
      const key = await generate(sdk, name);

      adminPage.on('dialog', (dialog) => dialog.accept());
      await adminPage.goto(`/kms/${encodeURIComponent(key.keyId)}`);
      await expect(adminPage.getByRole('heading', { name: keyText(name, key) })).toBeVisible({ timeout: 15000 });

      await adminPage.getByRole('button', { name: /rotate/i }).click();

      await expect(adminPage.getByText(/rotated/i).first()).toBeVisible();
      const after = await fetchKey(sdk, key.keyId);
      expect(after?.version ?? 0).toBeGreaterThan(key.version);
    });
  });

  test.describe('Error States', () => {
    test('shows the error the server returns for a duplicate key name', async ({ adminPage, sdk }) => {
      const name = keyName('Duplicate-Key');
      await generate(sdk, name);

      await adminPage.goto('/kms');
      await adminPage.getByRole('button', { name: /generate key/i }).click();
      await adminPage.locator('input#name').fill(name);
      await adminPage.getByRole('button', { name: /generate/i }).last().click();

      await expect(adminPage.getByText(/error|already exists/i).first()).toBeVisible();
    });
  });

  test.describe('Access Control', () => {
    test('redirects an unauthenticated browser to login', async ({ browser }) => {
      const context = await browser.newContext();
      const page = await context.newPage();
      try {
        await page.goto('/kms');
        await expect(page).toHaveURL(/\/auth\/webauthn/);
      } finally {
        await context.close();
      }
    });
  });

  test.describe('Key Details Actions', () => {
    test('disables a key from its details page', async ({ adminPage, sdk }) => {
      const name = keyName('disable-from-details');
      const key = await generate(sdk, name);

      adminPage.on('dialog', (dialog) => dialog.accept());
      await adminPage.goto(`/kms/${encodeURIComponent(key.keyId)}`);
      await adminPage.getByRole('button', { name: /disable/i }).click();

      await expect(adminPage.getByText(/disabled|success/i).first()).toBeVisible();
      expect((await fetchKey(sdk, key.keyId))?.status).toBe('DISABLED');
    });

    test('loads the details page of a key that can be deleted', async ({ adminPage, sdk }) => {
      const name = keyName('delete-from-details');
      const key = await generate(sdk, name);

      await adminPage.goto(`/kms/${encodeURIComponent(key.keyId)}`);

      await expect(adminPage.getByRole('heading', { name: keyText(name, key) })).toBeVisible();
    });
  });
});
