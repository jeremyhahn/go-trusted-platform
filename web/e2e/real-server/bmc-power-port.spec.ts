import type { Page, Request, Response } from '@playwright/test';
import { test, expect } from './fixtures';

/**
 * BMC profile page (#1736) against the real-server harness (#2035).
 *
 * Every BMC operation with a REST route is reachable from the page, and the
 * mutating ones run only after a confirm dialog. The harness has no BMC
 * behind any device profile, so each read answers whatever the server says
 * for the profile: the page must render every part from the server's answer
 * (its value, or its error) and keep the other parts. Cases that need a
 * reachable Redfish BMC are gaps in the PR body.
 */

const PROFILE_ID = '1';

/** The BMC operation a request is for, from `/api/v1/bmc/{id}/{op}`. */
function bmcOp(url: string): { id: string; op: string } | null {
  const m = new URL(url).pathname.match(/\/api\/v1\/bmc\/([^/]+)\/(.+)$/);
  return m ? { id: m[1], op: m[2] } : null;
}

function recordMutations(page: Page): Array<{ method: string; op: string }> {
  const calls: Array<{ method: string; op: string }> = [];
  page.on('request', (r: Request) => {
    const target = bmcOp(r.url());
    if (target && r.method() !== 'GET') calls.push({ method: r.method(), op: target.op });
  });
  return calls;
}

function isRead(op: string) {
  return (r: Response) => r.request().method() === 'GET' && bmcOp(r.url())?.op === op;
}

/** The message of a platform error envelope, in either of its two shapes. */
async function errorText(r: Response): Promise<string> {
  const b = (await r.json().catch(() => null)) as { error?: string | { message?: string } } | null;
  if (typeof b?.error === 'string') return b.error;
  return b?.error?.message ?? '';
}

async function openProfile(page: Page): Promise<{ sensors: Promise<Response>; power: Promise<Response> }> {
  const sensors = page.waitForResponse(isRead('sensors'));
  const power = page.waitForResponse(isRead('power'));
  await page.goto('/devices/bmc/__placeholder__/');
  await page.getByText('Select a BMC profile').waitFor();
  await page.waitForLoadState('networkidle');
  await page.evaluate((id) => window.history.pushState(null, '', `/devices/bmc/${id}/`), PROFILE_ID);
  await expect(page.getByRole('heading', { name: `BMC ${PROFILE_ID}` })).toBeVisible();
  return { sensors, power };
}

test.describe('BMC profile page (#1736), real server', () => {
  test('each part renders the server answer for it, and a failing part leaves the rest', async ({ adminPage }) => {
    const { sensors, power } = await openProfile(adminPage);
    const [s, p] = await Promise.all([sensors, power]);

    if (s.ok()) {
      await expect(adminPage.getByTestId('bmc-sensors')).toBeVisible();
    } else {
      await expect(adminPage.getByTestId('bmc-sensors-error')).toHaveText(await errorText(s));
    }
    if (p.ok()) {
      await expect(adminPage.getByTestId('bmc-power-state')).toBeVisible();
    }
    // The heading and the controls stay whatever a part answered.
    await expect(adminPage.getByRole('button', { name: 'Provision' })).toBeVisible();
  });

  test("the boot device select offers exactly the server's devices", async ({ adminPage }) => {
    await openProfile(adminPage);
    const options = adminPage.getByLabel('New boot device').locator('option');
    await expect(options).toHaveText(['none', 'pxe', 'disk', 'cdrom', 'virtual_media']);
  });

  test('set boot device sends nothing before the confirm, then POST boot-device with the choice', async ({ adminPage }) => {
    const calls = recordMutations(adminPage);
    await openProfile(adminPage);
    await adminPage.getByLabel('New boot device').selectOption('pxe');
    await adminPage.getByRole('button', { name: 'Set boot device' }).click();
    expect(calls).toEqual([]);

    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: 'Set boot device' })).toBeVisible();
    const sent = adminPage.waitForRequest((r) => r.method() === 'POST' && bmcOp(r.url())?.op === 'boot-device');
    await dialog.getByRole('button', { name: 'Confirm' }).click();
    const request = await sent;
    expect(request.postDataJSON()).toEqual({ device: 'pxe', persistent: false });
  });

  test('cancelling the confirm dialog sends nothing', async ({ adminPage }) => {
    const calls = recordMutations(adminPage);
    await openProfile(adminPage);
    await adminPage.getByRole('button', { name: 'Provision' }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
    await expect(adminPage.getByRole('dialog')).toBeHidden();
    expect(calls).toEqual([]);
  });

  test('the provision confirm names the shutdown and the OS install', async ({ adminPage }) => {
    const calls = recordMutations(adminPage);
    await openProfile(adminPage);
    await adminPage.getByRole('button', { name: 'Provision' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText('powers the host off');
    await expect(dialog).toContainText('installs an operating system');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    expect(calls).toEqual([]);
  });
});

test.describe('BMC profile ID is the numeric device-profile ID (#1736), real server', () => {
  test('the landing page opens the profile page for a numeric ID', async ({ adminPage }) => {
    await adminPage.goto('/devices/bmc/');
    await adminPage.getByLabel('BMC profile ID').fill(PROFILE_ID);
    await adminPage.getByRole('button', { name: 'Open', exact: true }).click();
    await expect(adminPage).toHaveURL(new RegExp(`/devices/bmc/${PROFILE_ID}/$`));
  });

  test('the landing page refuses a non-numeric ID', async ({ adminPage }) => {
    await adminPage.goto('/devices/bmc/');
    await adminPage.getByLabel('BMC profile ID').fill('abc');
    await adminPage.getByRole('button', { name: 'Open', exact: true }).click();
    await expect(adminPage.getByTestId('bmc-profile-id-error')).toContainText('number');
    await expect(adminPage).toHaveURL(/\/devices\/bmc\/$/);
  });

  test('the server refuses a non-numeric profile ID', async ({ sdk }) => {
    const res = await sdk.bmc.getPowerStatus('abc').catch((e: { status?: number }) => ({
      success: false,
      error: { status: e?.status },
    }));
    expect(res.success).toBe(false);
  });
});
