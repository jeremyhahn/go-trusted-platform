import type { Page } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The BMC certificate and users page (#2040, epic #1665) against the real
 * server: every write control is gated on the op the server reports in
 * GET /api/v1/capabilities, and the users card shows the server's refusal
 * for a profile that does not exist. No control is clicked.
 */

const UNKNOWN_PROFILE = '999999';

const BMC_WRITE_OPS = [
  'POST /api/v1/bmc/{profileID:[0-9]+}/enroll',
  'POST /api/v1/bmc/{profileID:[0-9]+}/cert/restore',
  'PUT /api/v1/bmc/{profileID:[0-9]+}/cert',
  'POST /api/v1/bmc/{profileID:[0-9]+}/users',
];

/** Opens the page for the unknown profile; resolves to the server's op -> enabled map. */
async function openPage(page: Page): Promise<Map<string, boolean>> {
  const capabilities = page.waitForResponse(
    (res) => res.request().method() === 'GET' && new URL(res.url()).pathname === '/api/v1/capabilities',
  );
  await page.goto('/devices/bmc/accounts');
  const res = await capabilities;
  await expect(page.getByRole('heading', { name: 'BMC certificate and users', exact: true })).toBeVisible();
  await page.getByLabel('BMC profile ID').fill(UNKNOWN_PROFILE);

  const payload = unwrapPayload<{ capabilities?: { op: string; enabled?: boolean }[] }>(await res.json());
  const enabled = new Map<string, boolean>();
  for (const c of payload.capabilities ?? []) enabled.set(c.op, c.enabled === true);
  return enabled;
}

test.describe('BMC certificate and users page', () => {
  test('each write control is gated as the server answers its op', async ({ adminPage }) => {
    const enabled = await openPage(adminPage);
    const controls = adminPage.locator('[data-capability-op]');
    await expect(controls.first()).toBeVisible();

    const ops = new Set<string>();
    for (const control of await controls.all()) {
      const op = await control.getAttribute('data-capability-op');
      expect(op).toBeTruthy();
      ops.add(op as string);
      await expect(control).toHaveAttribute('data-capability-enabled', String(enabled.get(op as string) === true));
    }
    for (const op of BMC_WRITE_OPS) expect(ops).toContain(op);
  });

  test('the users card shows the server refusal for an unknown profile', async ({ adminPage }) => {
    await openPage(adminPage);
    await expect(adminPage.getByText('BMC users unavailable').first()).toBeVisible();
  });
});
