import type { Locator, Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Device profiles against the real platformd (#2048, epic #1665).
 *
 * Read-only: no route mock and no write. Each assertion compares the page
 * with what the server answered.
 *
 * Covered: the profile count, the gating of the find-by-MAC, find-by-serial
 * and match lookups, and the Edit Profile dialog with its gated Save (opened
 * and cancelled, never saved) on /devices/profiles.
 */

const PROFILE_COUNT_OP = 'GET /api/v1/device/profiles/count';
const PROFILE_FIND_BY_MAC_OP = 'GET /api/v1/device/profiles/mac/{mac}';
const PROFILE_FIND_BY_SERIAL_OP = 'GET /api/v1/device/profiles/serial/{serial}';
const PROFILE_MATCH_OP = 'POST /api/v1/device/profiles/match';
const PROFILE_UPDATE_OP = 'PUT /api/v1/device/profiles/{id:[0-9]+}';

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

type Sdk = PlatformClient;

interface Capability {
  op: string;
  enabled: boolean;
  reason?: string;
}

/** The server's capability list, by op. */
async function capabilities(sdk: Sdk): Promise<Map<string, Capability>> {
  const res = await sdk.capabilities.list();
  expect(res.success, JSON.stringify(res.error)).toBeTruthy();
  const body = res.data as unknown as { capabilities?: Capability[] };
  return new Map((body.capabilities ?? []).map((c) => [c.op, c]));
}

/** The control carries the Gated attributes for op; a disabled op is disabled with its reason. */
async function expectGated(control: Locator, op: string, caps: Map<string, Capability>): Promise<void> {
  await expect(control).toHaveAttribute('data-capability-op', op);
  const cap = caps.get(op);
  if (cap && !cap.enabled) {
    await expect(control).toHaveAttribute('data-capability-enabled', 'false');
    await expect(control).toBeDisabled();
    await expect(control).toHaveAttribute('title', cap.reason ?? '');
  }
}

function profileCount(body: unknown): number {
  if (Array.isArray(body)) return body.length;
  const b = body as { profiles?: unknown[]; items?: unknown[] } | null;
  return (b?.profiles ?? b?.items ?? []).length;
}

test.describe('Device profiles against the real server', () => {
  test('the profiles page shows the count the server returns', async ({ adminPage, sdk }) => {
    const caps = await capabilities(sdk);
    const countCap = caps.get(PROFILE_COUNT_OP);
    const listRes = apiResponse(adminPage, /\/api\/v1\/device\/profiles$/);
    if (countCap && !countCap.enabled) {
      await adminPage.goto('/devices/profiles');
      await json<unknown>(await listRes);
      await expect(adminPage.getByTestId('device-profile-lookup')).toBeVisible();
      await expect(adminPage.getByTestId('device-profile-count')).toHaveCount(0);
      return;
    }
    const countRes = apiResponse(adminPage, /\/api\/v1\/device\/profiles\/count$/);
    await adminPage.goto('/devices/profiles');
    await json<unknown>(await listRes);
    const { count } = await json<{ count: number }>(await countRes);
    await expect(adminPage.getByTestId('device-profile-count')).toContainText(String(count));
  });

  test('the MAC, serial and match lookups are gated on their ops', async ({ adminPage, sdk }) => {
    const caps = await capabilities(sdk);
    await adminPage.goto('/devices/profiles');
    const lookup = adminPage.getByTestId('device-profile-lookup');
    await expect(lookup).toBeVisible();
    await expectGated(lookup.locator(`[data-capability-op="${PROFILE_FIND_BY_MAC_OP}"]`), PROFILE_FIND_BY_MAC_OP, caps);
    await expectGated(
      lookup.locator(`[data-capability-op="${PROFILE_FIND_BY_SERIAL_OP}"]`),
      PROFILE_FIND_BY_SERIAL_OP,
      caps,
    );
    await expectGated(lookup.locator(`[data-capability-op="${PROFILE_MATCH_OP}"]`), PROFILE_MATCH_OP, caps);
    await expect(lookup.getByLabel('Profile MAC address')).toBeVisible();
    await expect(lookup.getByLabel('Profile serial')).toBeVisible();
    await expect(lookup.getByLabel('Profile model')).toBeVisible();
  });

  test('Edit Profile opens a dialog whose Save is gated, and Cancel closes it', async ({ adminPage, sdk }) => {
    const caps = await capabilities(sdk);
    const listRes = apiResponse(adminPage, /\/api\/v1\/device\/profiles$/);
    await adminPage.goto('/devices/profiles');
    const total = profileCount(await json<unknown>(await listRes));
    if (total === 0) {
      await expect(adminPage.getByText('No device profiles found')).toBeVisible();
      return;
    }
    await adminPage.getByRole('button', { name: 'Open menu' }).first().click();
    await adminPage.getByRole('menuitem', { name: 'Edit Profile' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: 'Edit Profile' })).toBeVisible();
    await expect(dialog.getByLabel('Profile name')).toHaveValue(/.+/);
    await expectGated(dialog.getByRole('button', { name: 'Save' }), PROFILE_UPDATE_OP, caps);
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
  });
});
