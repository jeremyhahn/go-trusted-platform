import type { Locator, Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

// KMS key detail page against the real platformd (#2057, epic #1665): /kms/{id}
// shows the key GET /api/v1/kms/keys/{name} answers and the versions
// GET /api/v1/kms/keys/{name}/versions answers. No page.route mocks: the
// assertions follow what the server answered, never a fixed state. The Rotate,
// Disable and Enable buttons and the per-version toggles sit in the capability
// gate: their state follows GET /api/v1/capabilities.

/** The reason the capability gate gives for an operation the server does not list. */
const NOT_OFFERED = 'not offered by this server';

const ROTATE_OP = 'POST /api/v1/kms/keys/{name}/rotate';
const STATUS_OP = 'PUT /api/v1/kms/keys/{name}/status';

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

type Listed = Map<string, { enabled?: boolean; reason?: string }>;

async function expectGate(button: Locator, op: string, listed: Listed) {
  const cap = listed.get(op);
  const enabled = cap?.enabled === true;
  await expect(button).toHaveAttribute('data-capability-op', op);
  await expect(button).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
  if (!enabled) {
    await expect(button).toBeDisabled();
    await expect(button).toHaveAttribute('title', cap ? (cap.reason ?? '') : NOT_OFFERED);
  }
}

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

  test("the key detail page gates its key controls on the server's capabilities", async ({ adminPage, sdk }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed: Listed = new Map((res.data?.capabilities ?? []).map((c) => [c.op, c]));

    const list = await sdk.kms.listKeys();
    const listBody = (list.success ? list.data ?? {} : {}) as unknown as { keys?: KeyWire[] };
    const id = (listBody.keys ?? []).map((k) => k.key_id ?? k.id ?? k.name ?? '').find((n) => n !== '');
    if (id === undefined) return;
    const encoded = encodeURIComponent(id);

    const keyRes = apiResponse(adminPage, `/api/v1/kms/keys/${encoded}`);
    await adminPage.goto('/kms/' + encoded);
    if (!(await keyRes).ok()) return;
    await expect(adminPage.getByRole('heading', { level: 1 })).toBeVisible();

    const controls: Array<[string, string]> = [
      ['Rotate', ROTATE_OP],
      ['Disable', STATUS_OP],
      ['Enable', STATUS_OP],
    ];
    for (const [name, op] of controls) {
      const button = adminPage.getByRole('button', { name, exact: true });
      if ((await button.count()) > 0) await expectGate(button, op, listed);
    }

    const toggle = adminPage.getByRole('button', { name: /^(Disable|Enable) version \d+$/ }).first();
    if ((await toggle.count()) > 0) await expectGate(toggle, STATUS_OP, listed);
  });
});
