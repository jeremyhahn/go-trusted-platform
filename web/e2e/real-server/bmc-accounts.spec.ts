import type { Page } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The BMC certificate and users page (#2040, epic #1665) against the real
 * server: no card shows before a profile ID is typed; every write control is
 * gated on the op the server reports in GET /api/v1/capabilities, with the
 * server's reason (or "not offered by this server") as its title; the users
 * card shows the server's refusal for a profile that does not exist; and a
 * new profile ID remounts both cards. No control is clicked.
 */

const UNKNOWN_PROFILE = '999999';
const OTHER_UNKNOWN_PROFILE = '999998';

// Copied from CAPABILITY_NOT_OFFERED_REASON, web/src/hooks/use-capabilities.ts:29
// (specs do not import from src).
const NOT_OFFERED_REASON = 'not offered by this server';

// The write controls the page renders for a profile with no users: the
// certificate card offers Restore only and the users card offers Create.
const BMC_WRITE_OPS = [
  'POST /api/v1/bmc/{profileID:[0-9]+}/cert/restore',
  'POST /api/v1/bmc/{profileID:[0-9]+}/users',
];

// Ops this page renders no control for (#2199): enrolment is not on this page,
// and the web-certificate replace rotates no SPKI pin and no TLSA record.
const BMC_UNRENDERED_OPS = [
  'POST /api/v1/bmc/{profileID:[0-9]+}/enroll',
  'PUT /api/v1/bmc/{profileID:[0-9]+}/cert',
];

type Capability = { enabled: boolean; reason?: string };

const HEADING = 'BMC certificate and users';

/** Opens the page and checks its heading; types no profile and waits for no request. */
async function gotoPage(page: Page): Promise<void> {
  await page.goto('/devices/bmc/accounts');
  await expect(page.getByRole('heading', { name: HEADING, exact: true })).toBeVisible();
}

/**
 * Opens the page and types `id`; resolves to the server's op -> capability map.
 * The cards (and the Gated controls that read GET /api/v1/capabilities) mount
 * only once a profile ID is typed, so the response is awaited after the fill.
 */
async function openPage(page: Page, id = UNKNOWN_PROFILE): Promise<Map<string, Capability>> {
  const capabilities = page.waitForResponse(
    (res) => res.request().method() === 'GET' && new URL(res.url()).pathname === '/api/v1/capabilities',
  );
  await gotoPage(page);
  await enterProfile(page, id);
  const res = await capabilities;

  const payload = unwrapPayload<{ capabilities?: { op: string; enabled?: boolean; reason?: string }[] }>(
    await res.json(),
  );
  const caps = new Map<string, Capability>();
  for (const c of payload.capabilities ?? []) {
    caps.set(c.op, c.reason ? { enabled: c.enabled === true, reason: c.reason } : { enabled: c.enabled === true });
  }
  return caps;
}

/** Types a profile ID into the page's profile field. */
async function enterProfile(page: Page, id: string): Promise<void> {
  await page.getByLabel('BMC profile ID').fill(id);
}

test.describe('BMC certificate and users page', () => {
  test('each write control is gated as the server answers its op', async ({ adminPage }) => {
    const caps = await openPage(adminPage);
    const controls = adminPage.locator('[data-capability-op]');
    await expect(controls.first()).toBeVisible();

    const ops = new Set<string>();
    for (const control of await controls.all()) {
      const op = await control.getAttribute('data-capability-op');
      expect(op).toBeTruthy();
      ops.add(op as string);
      await expect(control).toHaveAttribute('data-capability-enabled', String(caps.get(op as string)?.enabled === true));
    }
    for (const op of BMC_WRITE_OPS) expect(ops).toContain(op);
    for (const op of BMC_UNRENDERED_OPS) {
      expect(ops).not.toContain(op);
      await expect(adminPage.locator(`[data-capability-op="${op}"]`)).toHaveCount(0);
    }
  });

  test('the users card shows the server refusal for an unknown profile', async ({ adminPage }) => {
    await openPage(adminPage);
    await expect(adminPage.getByText('BMC users unavailable').first()).toBeVisible();
  });

  test('shows no BMC card or control before a profile ID is typed', async ({ adminPage }) => {
    await gotoPage(adminPage);
    await expect(adminPage.getByText('BMC certificate', { exact: true })).toHaveCount(0);
    await expect(adminPage.getByText('BMC users', { exact: true })).toHaveCount(0);
    await expect(adminPage.locator('[data-capability-op]')).toHaveCount(0);

    await enterProfile(adminPage, UNKNOWN_PROFILE);
    await expect(adminPage.getByText('BMC certificate', { exact: true })).toBeVisible();
    await expect(adminPage.getByText('BMC users', { exact: true })).toBeVisible();
  });

  test('a BMC control the server does not list is disabled with the not-offered reason', async ({ adminPage }) => {
    const caps = await openPage(adminPage);
    const controls = adminPage.locator('[data-capability-op]');
    await expect(controls.first()).toBeVisible();

    for (const control of await controls.all()) {
      const op = await control.getAttribute('data-capability-op');
      expect(op).toBeTruthy();
      const cap = caps.get(op as string);
      if (!cap) {
        await expect(control).toBeDisabled();
        await expect(control).toHaveAttribute('title', NOT_OFFERED_REASON);
      } else if (!cap.enabled) {
        await expect(control).toBeDisabled();
        if (cap.reason) await expect(control).toHaveAttribute('title', cap.reason);
      } else {
        // The gate passes it on; a control can still be disabled by its own
        // form state (Create needs a slot, a name and a password).
        await expect(control).toHaveAttribute('data-capability-enabled', 'true');
        await expect(control).not.toHaveAttribute('title', NOT_OFFERED_REASON);
      }
    }
  });

  test('changing the profile ID remounts both cards', async ({ adminPage }) => {
    await openPage(adminPage);
    await expect(adminPage.getByText('BMC users unavailable').first()).toBeVisible();

    // The remounted users card lists the new profile's users afresh.
    const relisted = adminPage.waitForResponse(
      (res) =>
        res.request().method() === 'GET' &&
        new URL(res.url()).pathname.endsWith(`/bmc/${OTHER_UNKNOWN_PROFILE}/users`),
    );
    await enterProfile(adminPage, OTHER_UNKNOWN_PROFILE);
    await relisted;
    await expect(adminPage.getByText('BMC certificate', { exact: true })).toHaveCount(1);
    await expect(adminPage.getByText('BMC users', { exact: true })).toHaveCount(1);
    await expect(adminPage.getByText('BMC users unavailable').first()).toBeVisible();
  });
});
