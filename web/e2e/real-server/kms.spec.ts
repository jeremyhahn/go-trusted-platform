import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

// KMS pages against the real platformd (#2057, epic #1665): the key list
// shows what GET /api/v1/kms/keys answers, and every KMS control is gated on
// the server's GET /api/v1/capabilities listing. No page.route mocks: the
// assertions follow what the server answered, never a fixed state.

/** The reason the capability gate shows for an op the server does not list. */
const NOT_OFFERED = 'not offered by this server';

/** The key table shows ten rows per page. */
const PAGE_SIZE = 10;

function apiResponse(page: Page, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path,
  );
}

async function expectGated(page: Page, controls: Array<[string, string]>, listed: Map<string, { enabled?: boolean; reason?: string }>) {
  for (const [name, op] of controls) {
    const button = page.getByRole('button', { name, exact: true });
    const cap = listed.get(op);
    const enabled = cap?.enabled === true;
    await expect(button).toHaveAttribute('data-capability-op', op);
    await expect(button).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
    if (!enabled) {
      await expect(button).toBeDisabled();
      await expect(button).toHaveAttribute('title', cap ? (cap.reason ?? '') : NOT_OFFERED);
    }
  }
}

test.describe('KMS page', () => {
  test('the KMS page shows the keys the server lists', async ({ adminPage }) => {
    const keysRes = apiResponse(adminPage, '/api/v1/kms/keys');
    await adminPage.goto('/kms');
    const keys = await keysRes;

    if (keys.ok()) {
      const body = unwrapPayload<{ keys?: Array<{ name?: string; key_id?: string; id?: string }> }>(await keys.json());
      const listed = (body.keys ?? []).map((k) => k.name ?? k.key_id ?? k.id ?? '').filter((n) => n !== '');
      if (listed.length === 0) {
        await expect(adminPage.getByText('No results.', { exact: true })).toBeVisible();
      } else {
        for (const name of listed.slice(0, PAGE_SIZE)) {
          await expect(adminPage.getByText(name, { exact: true }).first()).toBeVisible();
        }
      }
    } else {
      await expect(adminPage.getByText('Error', { exact: true })).toBeVisible();
    }
  });

  test('the KMS page gates its controls on the server\'s capabilities', async ({ adminPage, sdk }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map((res.data?.capabilities ?? []).map((c) => [c.op, c]));

    await adminPage.goto('/kms');
    await expectGated(
      adminPage,
      [
        ['Generate random bytes', 'POST /api/v1/kms/random'],
        ['Hash', 'POST /api/v1/kms/hash'],
        ['Compute HMAC', 'POST /api/v1/kms/hmac/{name}'],
        ['Verify HMAC', 'POST /api/v1/kms/hmac/{name}/verify'],
        ['Update status', 'PUT /api/v1/kms/keys/{name}/status'],
        ['Import key', 'POST /api/v1/kms/keys/import'],
        ['Batch encrypt', 'POST /api/v1/kms/batch-encrypt'],
        ['Batch decrypt', 'POST /api/v1/kms/batch-decrypt'],
        ['Rewrap', 'POST /api/v1/kms/rewrap'],
      ],
      listed,
    );
  });

  test('the KMS page shows the backend status the server reports', async ({ adminPage }) => {
    const statusRes = apiResponse(adminPage, '/api/v1/kms/backend/status');
    await adminPage.goto('/kms');
    const status = await statusRes;

    const card = adminPage.getByTestId('kms-backend-status');
    if (status.ok()) {
      const body = unwrapPayload<{ backend_type?: string; status?: string }>(await status.json());
      await expect(adminPage.getByTestId('kms-backend-type')).toHaveText(body.backend_type || '-');
      await expect(adminPage.getByTestId('kms-backend-state')).toHaveText(body.status || '-');
    } else {
      await expect(card.getByText('Backend status could not be read')).toBeVisible();
    }
  });
});

test.describe('KMS data keys page', () => {
  test('the KMS data keys page gates its controls on the server\'s capabilities', async ({ adminPage, sdk }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map((res.data?.capabilities ?? []).map((c) => [c.op, c]));

    await adminPage.goto('/kms/data-keys');
    await expectGated(
      adminPage,
      [
        ['Generate data key', 'POST /api/v1/kms/data-keys'],
        ['Generate wrapped data key', 'POST /api/v1/kms/data-keys/wrapped'],
      ],
      listed,
    );
  });
});
