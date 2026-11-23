import type { Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Device activation check against the real platformd (#2048, epic #1665).
 *
 * No route mock: a device is seeded through the SDK per test and the
 * Activation check card on /devices/{id} posts POST
 * /api/v1/device/activate-json with its serial and an example MAC. That route
 * is a lookup, not an activation: the server either matches a profile and
 * reports the VLAN it admits, or refuses (for example no matching profile);
 * the page is compared with that answer and never says the device was
 * activated. When the server lists the op disabled, the control is disabled
 * with the server's reason and no POST is sent.
 */

const ACTIVATE_OP = 'POST /api/v1/device/activate-json';
const ACTIVATE_PATH = /\/api\/v1\/device\/activate-json$/;
const MAC = '02:00:00:00:00:01';

type Sdk = PlatformClient;

interface Seeded {
  id: string;
  serial: string;
}

async function seedDevice(sdk: Sdk): Promise<Seeded> {
  const serial = `e2e-act-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
  const res = await sdk.device.createDevice({ device: { serial } } as never);
  expect(res.success, JSON.stringify(res.error)).toBeTruthy();
  const { id } = res.data as unknown as { id: number | string };
  return { id: String(id), serial };
}

/** The server's reason when it lists the activation op disabled, else null. */
async function activateDisabledReason(sdk: Sdk): Promise<string | null> {
  const res = await sdk.capabilities.list();
  expect(res.success, JSON.stringify(res.error)).toBeTruthy();
  const body = res.data as unknown as {
    capabilities?: { op: string; enabled: boolean; reason?: string }[];
  };
  const cap = (body.capabilities ?? []).find((c) => c.op === ACTIVATE_OP);
  return cap && !cap.enabled ? (cap.reason ?? '') : null;
}

/** Waits for the page's own activation POST. */
function activateResponse(page: Page): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'POST' && ACTIVATE_PATH.test(new URL(r.url()).pathname),
  );
}

/** Counts the page's activation POSTs, from now on. */
function countPosts(page: Page): () => number {
  let n = 0;
  page.on('request', (r) => {
    if (r.method() === 'POST' && ACTIVATE_PATH.test(new URL(r.url()).pathname)) n += 1;
  });
  return () => n;
}

/** The error text of a refused response, as the SDK hands it to the card. */
async function errorMessage(r: Response): Promise<string> {
  const raw = (await r.json().catch(() => ({}))) as {
    error?: { message?: string } | string;
    message?: string;
  };
  if (typeof raw.error === 'string') return raw.error;
  return raw.error?.message ?? raw.message ?? '';
}

test.describe('Device activation against the real server', () => {
  test('the device page redirects to login without a session', async ({ page }) => {
    await page.goto('/devices/1');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('Check activation shows what the server answered', async ({ adminPage, sdk }) => {
    const dev = await seedDevice(sdk);
    const reason = await activateDisabledReason(sdk);
    const posts = countPosts(adminPage);

    await adminPage.goto(`/devices/${dev.id}`);
    const card = adminPage.getByTestId('device-activate-card');
    await expect(card).toBeVisible();
    await expect(card.getByLabel('Serial')).toHaveValue(dev.serial);
    await card.getByLabel('MAC address').fill(MAC);
    const activate = card.getByRole('button', { name: 'Check activation' });

    if (reason !== null) {
      await expect(activate).toBeDisabled();
      await expect(activate).toHaveAttribute('title', reason);
      expect(posts()).toBe(0);
      return;
    }

    const pending = activateResponse(adminPage);
    await activate.click();
    const res = await pending;
    expect(res.request().postDataJSON()).toEqual({ serial: dev.serial, mac_address: MAC });

    if (res.ok()) {
      const answer = unwrapPayload<{ status: string; vlan?: number; transitioned_at?: string }>(await res.json());
      await expect(adminPage.getByText('Activation check').first()).toBeVisible();
      await expect(adminPage.getByText('Device activated')).toHaveCount(0);
      if (answer.vlan !== undefined) {
        await expect(adminPage.getByText(`Admitted VLAN ${answer.vlan}.`).first()).toBeVisible();
      }
    } else {
      await expect(adminPage.getByText('Activation check failed').first()).toBeVisible();
      const message = await errorMessage(res);
      if (message !== '') {
        await expect(adminPage.getByText(message, { exact: false }).first()).toBeVisible();
      }
    }
  });
});
