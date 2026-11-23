import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

// KMS key detail page against the real platformd (#2057, epic #1665): /kms/{id}
// shows the key GET /api/v1/kms/keys/{name} answers and the versions
// GET /api/v1/kms/keys/{name}/versions answers. No page.route mocks: the
// assertions follow what the server answered, never a fixed state. The Rotate,
// Disable and Enable gates are asserted after lane s2057b's gating lands.

/** The id used when the server lists no key: the page must show its error or not-found state. */
const ABSENT_KEY = 'e2e-absent-key';

/** At most this many version numbers are checked. */
const MAX_VERSIONS = 10;

function apiResponse(page: Page, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path,
  );
}

type KeyWire = { name?: string; key_id?: string; id?: string };

test.describe('KMS key detail page', () => {
  test('the key detail page shows the key and versions the server answers', async ({ adminPage, sdk }) => {
    const list = await sdk.kms.listKeys();
    const listBody = (list.success ? list.data ?? {} : {}) as unknown as { keys?: KeyWire[] };
    const first = (listBody.keys ?? []).map((k) => k.key_id ?? k.id ?? k.name ?? '').find((n) => n !== '');
    const id = first ?? ABSENT_KEY;
    const encoded = encodeURIComponent(id);

    const keyRes = apiResponse(adminPage, `/api/v1/kms/keys/${encoded}`);
    const versionsRes = apiResponse(adminPage, `/api/v1/kms/keys/${encoded}/versions`);
    // The page may close before the versions read when the key read fails.
    versionsRes.catch(() => undefined);
    await adminPage.goto('/kms/' + encoded);
    const key = await keyRes;

    if (!key.ok()) {
      await expect(adminPage.getByText(/Error loading key|Key not found/)).toBeVisible();
      return;
    }

    const body = unwrapPayload<KeyWire & { key?: KeyWire; metadata?: KeyWire }>(await key.json());
    const name = body.metadata?.name || body.key?.name || body.name || id;
    await expect(adminPage.getByRole('heading', { level: 1 })).toHaveText(name);

    const versions = await versionsRes;
    if (!versions.ok()) {
      await expect(adminPage.getByText('Key versions could not be read')).toBeVisible();
      return;
    }
    const served = unwrapPayload<{ versions?: Array<{ version?: number }> }>(await versions.json()).versions ?? [];
    const numbers = served.map((v) => v.version).filter((v): v is number => typeof v === 'number');
    if (numbers.length > 0) {
      await expect(adminPage.getByText('Key Versions', { exact: true })).toBeVisible();
      for (const n of numbers.slice(0, MAX_VERSIONS)) {
        await expect(adminPage.getByRole('cell', { name: String(n), exact: true }).first()).toBeVisible();
      }
    }
  });
});
