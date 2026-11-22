/**
 * Storage pages against the real-server harness (#2036, epic #1665).
 *
 * Ported from web/e2e/storage.spec.ts, whose mocked suites were all skipped.
 * Buckets and objects are created through the SDK and every create or delete
 * the page makes is checked against the server afterwards. The key-value,
 * vector, time-series and backup pages are opened against the real server;
 * their mocked CRUD flows, the injected 500/409 errors and the member session
 * have no seeding path or server behaviour behind them here and are listed as
 * gaps in the PR body.
 */
import type { Page } from '@playwright/test';
import { test, expect } from './fixtures';

interface Result<T> {
  success: boolean;
  data?: T;
  error?: unknown;
}

/** The parts of the SDK's object storage services these specs drive. */
interface StorageSdk {
  quicBaaSObjectStorageAdmin: {
    createBucket(req: { name: string; region?: string }): Promise<Result<unknown>>;
    deleteBucket(req: { name: string; force?: boolean }): Promise<Result<unknown>>;
    listBuckets(): Promise<Result<{ buckets: Array<{ name: string }> }>>;
  };
  quicBaaSObjectStorage: {
    putObject(req: { bucket: string; key: string; content: string; contentType?: string }): Promise<Result<unknown>>;
    listObjects(req: { bucket: string }): Promise<Result<{ objects: Array<{ key: string }> }>>;
  };
}

/** A bucket name unique per call (lowercase, DNS-safe). */
function bucketName(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6).toString(36)}`;
}

async function seedBucket(sdk: unknown, prefix: string): Promise<string> {
  const name = bucketName(prefix);
  const res = await (sdk as StorageSdk).quicBaaSObjectStorageAdmin.createBucket({ name });
  expect(res.success, JSON.stringify(res.error)).toBe(true);
  return name;
}

async function seedObject(sdk: unknown, bucket: string, key: string): Promise<void> {
  const content = Buffer.from(`e2e ${key}`).toString('base64');
  const res = await (sdk as StorageSdk).quicBaaSObjectStorage.putObject({
    bucket,
    key,
    content,
    contentType: 'text/plain',
  });
  expect(res.success, JSON.stringify(res.error)).toBe(true);
}

async function serverBuckets(sdk: unknown): Promise<string[]> {
  const res = await (sdk as StorageSdk).quicBaaSObjectStorageAdmin.listBuckets();
  expect(res.success, JSON.stringify(res.error)).toBe(true);
  return (res.data?.buckets ?? []).map((b) => b.name);
}

async function serverObjects(sdk: unknown, bucket: string): Promise<string[]> {
  const res = await (sdk as StorageSdk).quicBaaSObjectStorage.listObjects({ bucket });
  expect(res.success, JSON.stringify(res.error)).toBe(true);
  return (res.data?.objects ?? []).map((o) => o.key);
}

async function openObjects(page: Page): Promise<void> {
  await page.goto('/storage/objects');
  await expect(page.getByRole('heading', { name: /object storage/i })).toBeVisible();
}

test.describe('Storage - Object Storage', () => {
  test.describe('Buckets', () => {
    test('lists the buckets the server holds', async ({ adminPage, sdk }) => {
      const names = [await seedBucket(sdk, 'e2e-assets'), await seedBucket(sdk, 'e2e-backup')];

      await openObjects(adminPage);

      for (const name of names) {
        await expect(adminPage.getByText(name).first()).toBeVisible();
      }
    });

    test('creates a bucket the server then lists', async ({ adminPage, sdk }) => {
      const name = bucketName('e2e-new');

      await openObjects(adminPage);
      await adminPage.getByRole('button', { name: /create bucket/i }).click();
      await adminPage.fill('input#bucketName', name);
      await adminPage.getByRole('button', { name: /create bucket/i }).last().click();

      await expect(adminPage.getByText(/bucket created/i)).toBeVisible();
      await expect.poll(() => serverBuckets(sdk)).toContain(name);
    });

    test('refuses an empty bucket name before any request', async ({ adminPage }) => {
      const creates: string[] = [];
      adminPage.on('request', (req) => {
        if (req.method() === 'POST' && /bucket/i.test(req.url())) creates.push(req.url());
      });

      await openObjects(adminPage);
      await adminPage.getByRole('button', { name: /create bucket/i }).click();
      await adminPage.getByRole('button', { name: /create bucket/i }).last().click();

      await expect(adminPage.getByText(/bucket name is required/i)).toBeVisible();
      expect(creates).toHaveLength(0);
    });

    test('shows the server refusal for a bucket name already taken', async ({ adminPage, sdk }) => {
      const name = await seedBucket(sdk, 'e2e-taken');

      await openObjects(adminPage);
      await adminPage.getByRole('button', { name: /create bucket/i }).click();
      await adminPage.fill('input#bucketName', name);
      await adminPage.getByRole('button', { name: /create bucket/i }).last().click();

      await expect(adminPage.getByText(/error creating bucket/i)).toBeVisible();
    });

    test('deletes a bucket after confirmation', async ({ adminPage, sdk }) => {
      const name = await seedBucket(sdk, 'e2e-delete');

      await openObjects(adminPage);
      adminPage.on('dialog', (dialog) => dialog.accept());
      const row = adminPage.locator('div, tr').filter({ hasText: name }).last();
      await row.locator('button').filter({ has: adminPage.locator('svg.text-destructive') }).first().click();

      await expect(adminPage.getByText(/bucket deleted/i)).toBeVisible();
      await expect.poll(() => serverBuckets(sdk)).not.toContain(name);
    });

    test('selects a bucket to view its objects', async ({ adminPage, sdk }) => {
      const name = await seedBucket(sdk, 'e2e-select');

      await openObjects(adminPage);
      await adminPage.getByText(name).first().click();

      await expect(adminPage.getByText(name).nth(1)).toBeVisible();
    });
  });

  test.describe('Objects', () => {
    test('lists the objects the server holds in the selected bucket', async ({ adminPage, sdk }) => {
      const bucket = await seedBucket(sdk, 'e2e-objects');
      const keys = ['file1.txt', 'folder/file2.txt'];
      for (const key of keys) {
        await seedObject(sdk, bucket, key);
      }

      await openObjects(adminPage);
      await adminPage.getByText(bucket).first().click();

      for (const key of keys) {
        await expect(adminPage.getByText(key)).toBeVisible();
      }
    });

    test('shows the empty state for a bucket with no objects', async ({ adminPage, sdk }) => {
      const bucket = await seedBucket(sdk, 'e2e-empty');
      expect(await serverObjects(sdk, bucket)).toHaveLength(0);

      await openObjects(adminPage);
      await adminPage.getByText(bucket).first().click();

      await expect(adminPage.getByText(/no objects found/i)).toBeVisible();
    });

    test('opens the upload dialog', async ({ adminPage, sdk }) => {
      const bucket = await seedBucket(sdk, 'e2e-upload');

      await openObjects(adminPage);
      await adminPage.getByText(bucket).first().click();
      await adminPage.getByRole('button', { name: /upload object/i }).click();

      await expect(adminPage.getByRole('dialog')).toBeVisible();
      await expect(adminPage.getByRole('heading', { name: /upload object/i })).toBeVisible();
    });

    test('deletes an object after confirmation', async ({ adminPage, sdk }) => {
      const bucket = await seedBucket(sdk, 'e2e-objdel');
      await seedObject(sdk, bucket, 'delete-me.txt');

      await openObjects(adminPage);
      await adminPage.getByText(bucket).first().click();
      await expect(adminPage.getByText('delete-me.txt')).toBeVisible();
      adminPage.on('dialog', (dialog) => dialog.accept());
      await adminPage.locator('button').filter({ hasText: /more/i }).first().click();
      await adminPage.getByRole('menuitem', { name: /delete/i }).click();

      await expect(adminPage.getByText(/object deleted/i)).toBeVisible();
      await expect.poll(() => serverObjects(sdk, bucket)).not.toContain('delete-me.txt');
    });

    test('starts a download of an object', async ({ adminPage, sdk }) => {
      const bucket = await seedBucket(sdk, 'e2e-download');
      await seedObject(sdk, bucket, 'download-me.txt');

      await openObjects(adminPage);
      await adminPage.getByText(bucket).first().click();
      await expect(adminPage.getByText('download-me.txt')).toBeVisible();
      await adminPage.locator('button').filter({ hasText: /more/i }).first().click();
      await adminPage.getByRole('menuitem', { name: /download/i }).click();

      await expect(adminPage.getByText(/download started/i)).toBeVisible();
    });
  });
});

test.describe('Storage - other pages', () => {
  for (const [path, heading] of [
    ['/storage/kv', /key-value store/i],
    ['/storage/vector', /vector database/i],
    ['/storage/timeseries', /time series database/i],
    ['/storage/backup', /backup & restore/i],
  ] as const) {
    test(`opens ${path} against the server`, async ({ adminPage }) => {
      await adminPage.goto(path);

      await expect(adminPage.getByRole('heading', { name: heading })).toBeVisible();
    });
  }
});

test.describe('Storage - Access Control', () => {
  test('redirects an unauthenticated browser to login', async ({ browser }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    try {
      await page.goto('/storage/objects');
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    } finally {
      await context.close();
    }
  });
});
