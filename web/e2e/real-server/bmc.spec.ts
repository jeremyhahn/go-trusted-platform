import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The BMC page (row #2039) against the real server: every write control is
 * gated on the server's own GET /api/v1/capabilities answer, and the cards
 * show the server's refusal for a BMC profile the test daemon does not have.
 * No control is clicked: the spec reads, it never powers, boots, mounts or
 * provisions anything.
 */

// A BMC profile ID the test daemon has no profile for.
const UNKNOWN_PROFILE_ID = '999999';

interface Capability {
  op: string;
  enabled?: boolean;
}

function capabilitiesResponse(page: Page): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === '/api/v1/capabilities',
  );
}

async function openBMCPage(page: Page): Promise<Map<string, boolean>> {
  const answer = capabilitiesResponse(page);
  await page.goto('/devices/bmc');
  await expect(page.getByRole('heading', { name: 'BMC', exact: true })).toBeVisible();
  await page.getByLabel('BMC profile ID').fill(UNKNOWN_PROFILE_ID);
  const r = await answer;
  expect(r.ok(), `GET /api/v1/capabilities answered ${r.status()}`).toBe(true);
  const payload = unwrapPayload<{ capabilities?: Capability[] }>(await r.json());
  return new Map((payload.capabilities ?? []).map((c) => [c.op, c.enabled === true]));
}

test.describe('BMC page', () => {
  test('each write control is gated as the server answers its op', async ({ adminPage }) => {
    const enabled = await openBMCPage(adminPage);

    const controls = adminPage.locator('[data-capability-op]');
    await expect(controls.first()).toBeVisible();
    const count = await controls.count();
    expect(count, 'the BMC cards carry gated write controls').toBeGreaterThan(0);

    const ops = new Set<string>();
    for (let i = 0; i < count; i++) {
      const control = controls.nth(i);
      const op = await control.getAttribute('data-capability-op');
      expect(op, `control ${i} names its op`).toBeTruthy();
      ops.add(op as string);
      // An op the server leaves out of its answer is disabled.
      const want = enabled.get(op as string) === true;
      await expect(control, `${op} gate`).toHaveAttribute('data-capability-enabled', String(want));
    }

    for (const op of [
      'POST /api/v1/bmc/{profileID:[0-9]+}/power',
      'POST /api/v1/bmc/{profileID:[0-9]+}/boot-device',
      'POST /api/v1/bmc/{profileID:[0-9]+}/virtual-media',
      'DELETE /api/v1/bmc/{profileID:[0-9]+}/virtual-media',
      'POST /api/v1/bmc/{profileID:[0-9]+}/provision',
    ]) {
      expect(ops.has(op), `a control is gated on ${op}`).toBe(true);
    }
  });

  test('the power state shows the server refusal for an unknown profile', async ({ adminPage }) => {
    await openBMCPage(adminPage);
    await expect(adminPage.getByTestId('bmc-power-state')).toContainText('Power state unavailable:');
  });
});
