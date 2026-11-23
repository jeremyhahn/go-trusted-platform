import type { Page, Response } from '@playwright/test';
import type { ApiResponse, CapabilitiesResponse, PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload, wireCount } from './fixtures/wire';

/**
 * Proxy pools page against the real platformd (#2061, epic #1665).
 *
 * Covers ListPools, GetPool, CreatePool, UpdatePool, DeletePool,
 * GetProxyConfig and GetZoneMatrix with no route mocks: every assertion
 * compares the page with what the server answered, and every case follows
 * the server's capability answer (a dark op shows its not-enabled state or
 * a disabled control whose title is the reason).
 */

const LIST_POOLS = 'GET /api/v1/proxy/pools';
const GET_CONFIG = 'GET /api/v1/proxy/config';
const GET_ZONE_MATRIX = 'GET /api/v1/proxy/zone-matrix';
const CREATE_POOL = 'POST /api/v1/proxy/pools';
const UPDATE_POOL = 'PUT /api/v1/proxy/pools/{id}';
const DELETE_POOL = 'DELETE /api/v1/proxy/pools/{id}';

/** The pool platformd.test.yaml seeds. */
const SEEDED_POOL = 'control-plane-console';

/** The data of a successful SDK answer; fails the test on a refusal. */
function sdkData<T>(res: ApiResponse<T>, what: string): T {
  expect(res.success, `${what}: ${JSON.stringify(res.error)}`).toBeTruthy();
  if (res.data === undefined) throw new Error(`${what}: no data`);
  return res.data;
}

interface Capabilities {
  on(op: string): boolean;
  reason(op: string): string;
}

/** The server's capability answer, read through the SDK. */
async function capabilities(sdk: PlatformClient): Promise<Capabilities> {
  const caps: CapabilitiesResponse = sdkData(await sdk.capabilities.list(), 'capabilities');
  const find = (op: string) => caps.capabilities.find((c) => c.op === op);
  return {
    on: (op) => find(op)?.enabled === true,
    reason: (op) => find(op)?.reason ?? '',
  };
}

/** Waits for the page's own GET whose path matches. */
function apiResponse(page: Page, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && path.test(new URL(r.url()).pathname),
  );
}

async function json<T>(r: Response): Promise<T> {
  expect(r.ok(), `${r.url()} answered ${r.status()}`).toBeTruthy();
  return unwrapPayload<T>(await r.json());
}

/** The <dd> after the <dt> labelled term in the card. */
function definition(page: Page, card: string, term: string) {
  return page
    .getByTestId(card)
    .locator('dt', { hasText: term })
    .locator('xpath=following-sibling::dd[1]');
}

test.describe('proxy pools against the real platformd (#2061)', () => {
  test('lists the pools the server answers', async ({ adminPage, sdk }) => {
    const caps = await capabilities(sdk);
    const on = caps.on;

    if (!on(LIST_POOLS)) {
      await adminPage.goto('/networking/proxy/pools');
      await expect(adminPage.getByTestId('proxy-not-enabled')).toBeVisible();
      await expect(adminPage.getByTestId('proxy-not-enabled')).toContainText(caps.reason(LIST_POOLS));
      return;
    }

    const poolsRes = apiResponse(adminPage, /\/api\/v1\/proxy\/pools$/);
    await adminPage.goto('/networking/proxy/pools');
    const { pools } = await json<{ pools?: Array<{ id?: string }> }>(await poolsRes);
    const ids = (pools ?? []).map((p) => p.id ?? '');
    expect(ids).toContain(SEEDED_POOL);
    for (const id of ids) {
      await expect(adminPage.getByTestId(`proxy-pool-${id}`)).toBeVisible();
    }
    await expect(adminPage.getByTestId('proxy-not-enabled')).toHaveCount(0);
  });

  test('shows the merged config and the zone matrix the server answers', async ({ adminPage, sdk }) => {
    const caps = await capabilities(sdk);
    const on = caps.on;
    await adminPage.goto('/networking/proxy/pools');

    if (on(GET_CONFIG)) {
      const config = sdkData(await sdk.proxy.getConfig(), 'getConfig');
      await expect(definition(adminPage, 'proxy-config', 'Version')).toHaveText(String(config.version ?? '-'));
      await expect(definition(adminPage, 'proxy-config', 'Routes')).toHaveText(
        String(wireCount((config.routes ?? []).length)),
      );
      await expect(definition(adminPage, 'proxy-config', 'Pools')).toHaveText(
        String(wireCount((config.pools ?? []).length)),
      );
    } else {
      // The page makes no read: the card keeps its empty values.
      await expect(definition(adminPage, 'proxy-config', 'Version')).toHaveText('-');
    }

    const matrixCard = adminPage.getByTestId('proxy-zone-matrix');
    if (on(GET_ZONE_MATRIX)) {
      const matrix = sdkData(await sdk.proxy.getZoneMatrix(), 'getZoneMatrix');
      for (const zone of matrix.zones ?? []) {
        await expect(matrixCard.getByText(zone, { exact: true }).first()).toBeVisible();
      }
      if ((matrix.pairs ?? []).length === 0) {
        await expect(matrixCard.getByText('No zone pairs allowed.')).toBeVisible();
      } else {
        await expect(matrixCard.locator('tbody tr')).toHaveCount((matrix.pairs ?? []).length);
      }
    } else {
      await expect(matrixCard.getByText('No zone pairs allowed.')).toBeVisible();
    }

    if (!on(LIST_POOLS)) {
      await expect(adminPage.getByTestId('proxy-not-enabled')).toContainText(caps.reason(LIST_POOLS));
    }
  });

  test('creates, edits and deletes a pool', async ({ adminPage, sdk }) => {
    const caps = await capabilities(sdk);
    const on = caps.on;

    const writes = [CREATE_POOL, UPDATE_POOL, DELETE_POOL];
    if (!on(LIST_POOLS) || writes.some((op) => !on(op))) {
      await adminPage.goto('/networking/proxy/pools');
      if (!on(CREATE_POOL)) {
        const button = adminPage.getByRole('button', { name: 'New pool' });
        await expect(button).toBeDisabled();
        await expect(button).toHaveAttribute('title', caps.reason(CREATE_POOL));
      }
      if (on(LIST_POOLS)) {
        for (const [op, verb] of [
          [UPDATE_POOL, 'Edit'],
          [DELETE_POOL, 'Delete'],
        ] as const) {
          if (on(op)) continue;
          const button = adminPage.getByRole('button', { name: `${verb} ${SEEDED_POOL}` });
          await expect(button).toBeDisabled();
          await expect(button).toHaveAttribute('title', caps.reason(op));
        }
      }
      return;
    }

    const id = `e2e-pool-${Date.now()}`;
    const first = 'https://192.0.2.10:8443';
    const second = 'https://192.0.2.11:8443';
    const row = adminPage.getByTestId(`proxy-pool-${id}`);
    try {
      await adminPage.goto('/networking/proxy/pools');
      await expect(adminPage.getByTestId(`proxy-pool-${SEEDED_POOL}`)).toBeVisible();

      // CreatePool through the dialog.
      await adminPage.getByRole('button', { name: 'New pool' }).click();
      const create = adminPage.getByRole('dialog');
      await create.getByLabel('Pool ID').fill(id);
      await create.getByLabel('Backends').fill(first);
      await create.getByLabel('Balancer').fill('round-robin');
      await create.getByRole('button', { name: 'Save' }).click();
      await expect(create).toBeHidden();
      await expect(row).toBeVisible();

      const created = sdkData(await sdk.proxy.getPool(id), 'getPool after create');
      expect(created.pool?.id).toBe(id);
      expect((created.pool?.backends ?? []).map((b) => b.url)).toEqual([first]);

      // UpdatePool: GetPool fills the dialog, a second backend is added.
      await adminPage.getByRole('button', { name: `Edit ${id}` }).click();
      const edit = adminPage.getByRole('dialog');
      const backends = edit.getByLabel('Backends');
      await expect(backends).toHaveValue(new RegExp(`^${first.replace(/[.]/g, '\\.')}`));
      await backends.fill(`${first}\n${second}`);
      await edit.getByRole('button', { name: 'Save' }).click();
      await expect(edit).toBeHidden();

      const updated = sdkData(await sdk.proxy.getPool(id), 'getPool after update');
      expect((updated.pool?.backends ?? []).map((b) => b.url)).toEqual([first, second]);

      // DeletePool through the confirm dialog.
      await adminPage.getByRole('button', { name: `Delete ${id}` }).click();
      const confirm = adminPage.getByRole('dialog').filter({ hasText: 'Delete pool' });
      await expect(confirm).toBeVisible();
      await confirm.getByRole('button', { name: 'Delete', exact: true }).click();
      await expect(confirm).toBeHidden();
      await expect(row).toHaveCount(0);

      const gone = await sdk.proxy.getPool(id);
      expect(gone.success).toBeFalsy();
    } finally {
      const left = await sdk.proxy.getPool(id);
      if (left.success && left.data?.pool) {
        await sdk.proxy.deletePool(id);
      }
    }
  });
});
