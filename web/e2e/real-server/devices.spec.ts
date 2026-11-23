import type { Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Devices against the real platformd (#2048, epic #1665).
 *
 * No route mock: two devices are seeded through the SDK per test and
 * each assertion compares the page with what the server answered.
 *
 * Covered: the device count and find-by-serial on /devices, the model edit
 * and the 409 for a serial another device holds on /devices/{id}.
 * Not covered: the attest card (needs a TPM-backed device the test daemon
 * does not have).
 */

const DEVICE_UPDATE_OP = 'PUT /api/v1/devices/{id:[0-9]+}';

/** Waits for the page's own GET whose path matches, and returns its JSON. */
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

interface Seeded {
  id: string;
  serial: string;
}

async function seedDevice(sdk: Sdk, suffix: string): Promise<Seeded> {
  const serial = `e2e-dev-${Date.now().toString(36)}-${suffix}`;
  const res = await sdk.device.createDevice({ device: { serial } } as never);
  expect(res.success, JSON.stringify(res.error)).toBeTruthy();
  const { id } = res.data as unknown as { id: number | string };
  return { id: String(id), serial };
}

async function seedTwo(sdk: Sdk): Promise<[Seeded, Seeded]> {
  const a = await seedDevice(sdk, 'a');
  const b = await seedDevice(sdk, 'b');
  return [a, b];
}

/** The server's reason when it lists the device update op disabled, else null. */
async function updateDisabledReason(sdk: Sdk): Promise<string | null> {
  const res = await sdk.capabilities.list();
  expect(res.success, JSON.stringify(res.error)).toBeTruthy();
  const body = res.data as unknown as {
    capabilities?: { op: string; enabled: boolean; reason?: string }[];
  };
  const cap = (body.capabilities ?? []).find((c) => c.op === DEVICE_UPDATE_OP);
  return cap && !cap.enabled ? (cap.reason ?? '') : null;
}

async function readDevice(sdk: Sdk, id: string): Promise<{ model?: string; serial?: string }> {
  const res = await sdk.device.getDevice(id);
  expect(res.success, JSON.stringify(res.error)).toBeTruthy();
  const body = res.data as unknown as {
    device?: { model?: string; serial?: string };
    model?: string;
    serial?: string;
  };
  return body.device ?? body;
}

test.describe('Devices against the real server', () => {
  test('the devices list shows the count the server returns', async ({ adminPage, sdk }) => {
    await seedTwo(sdk);
    const countRes = apiResponse(adminPage, /\/api\/v1\/devices\/count$/);
    await adminPage.goto('/devices');
    const { count } = await json<{ count: number }>(await countRes);
    await expect(adminPage.getByTestId('device-count')).toContainText(String(count));
  });

  test('find by serial opens the device page', async ({ adminPage, sdk }) => {
    const [a] = await seedTwo(sdk);
    await adminPage.goto('/devices');
    await adminPage.getByLabel('Find by serial').fill(a.serial);
    await adminPage.getByRole('button', { name: 'Find' }).click();
    await expect(adminPage).toHaveURL(new RegExp(`/devices/${a.id}$`));
  });

  test('the model edit is saved and re-read', async ({ adminPage, sdk }) => {
    const [a] = await seedTwo(sdk);
    const reason = await updateDisabledReason(sdk);
    await adminPage.goto(`/devices/${a.id}`);
    const card = adminPage.getByTestId('device-model-card');
    const save = adminPage.getByTestId('device-model-save');
    if (reason !== null) {
      await expect(save).toBeDisabled();
      await expect(save).toHaveAttribute('title', reason);
      return;
    }
    await card.getByLabel('Model').fill('X11-e2e');
    await save.click();
    await expect(adminPage.getByText('Device updated').first()).toBeVisible();
    await expect.poll(async () => (await readDevice(sdk, a.id)).model).toBe('X11-e2e');
  });

  test('a serial another device holds is refused', async ({ adminPage, sdk }) => {
    const [a, b] = await seedTwo(sdk);
    const reason = await updateDisabledReason(sdk);
    await adminPage.goto(`/devices/${a.id}`);
    const card = adminPage.getByTestId('device-serial-card');
    const save = adminPage.getByTestId('device-serial-save');
    if (reason !== null) {
      await expect(save).toBeDisabled();
      await expect(save).toHaveAttribute('title', reason);
      return;
    }
    await card.getByLabel('Serial').fill(b.serial);
    await save.click();
    await expect(adminPage.getByText('Update refused').first()).toBeVisible();
    expect((await readDevice(sdk, a.id)).serial).toBe(a.serial);
  });
});
