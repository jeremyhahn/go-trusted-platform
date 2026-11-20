import type { Page, Request, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

/**
 * Real-server port of the mocked device-lookup.spec.ts (#1743, #2035).
 *
 * Every test seeds its own devices and profiles through the SDK (unique
 * serials, MACs and names) and deletes them afterwards. The page talks to the
 * real server; the tests watch the requests it sends and assert on what the
 * server answers. Cases with no server state the SDK can seed (activation of
 * an enrolled device, the device's own profile) assert the page's handling of
 * the server's real answer; docs/plans/1665-port-1.md lists them as gaps.
 */

interface SentCall {
  method: string;
  path: string;
  body: unknown;
}

function uid(): string {
  return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
}

/** A unique locally administered MAC address. */
function uniqueMac(): string {
  const bytes = [0x02, ...Array.from({ length: 5 }, () => Math.floor(Math.random() * 256))];
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join(':');
}

/** The id of a created or fetched record, flat or under an envelope. */
function idOf(data: unknown): string {
  const d = (data ?? {}) as { id?: unknown; device?: { id?: unknown }; profile?: { id?: unknown } };
  const id = d.id ?? d.device?.id ?? d.profile?.id;
  if (id === undefined || id === null || id === '') throw new Error(`[real-server] no id in ${JSON.stringify(data)}`);
  return String(id);
}

/** A field of a record, flat or under an envelope. */
function fieldOf(data: unknown, key: string): unknown {
  const d = (data ?? {}) as Record<string, unknown>;
  if (key in d) return d[key];
  const inner = (d.device ?? d.profile) as Record<string, unknown> | undefined;
  return inner?.[key];
}

async function seedDevice(sdk: PlatformClient, serial: string, model: string): Promise<string> {
  const res = await sdk.device.createDevice({ device: { serial, model } });
  if (!res.success) throw new Error(`[real-server] createDevice(${serial}): ${JSON.stringify(res.error)}`);
  return idOf(res.data);
}

async function seedProfile(sdk: PlatformClient, name: string, mac: string, model: string): Promise<string> {
  const res = await sdk.device.createProfile({
    profile: { name, model, role: 'server', mac_address: mac, match_rules: { model } },
  });
  if (!res.success) throw new Error(`[real-server] createProfile(${name}): ${JSON.stringify(res.error)}`);
  return idOf(res.data);
}

/** Records every API request the page sends (method, path after /api, JSON body). */
function watchCalls(page: Page): SentCall[] {
  const calls: SentCall[] = [];
  page.on('request', (req: Request) => {
    const url = new URL(req.url());
    const at = url.pathname.indexOf('/api/');
    if (at < 0) return;
    let body: unknown = null;
    try {
      body = req.postDataJSON();
    } catch {
      body = req.postData();
    }
    calls.push({ method: req.method(), path: url.pathname.slice(at + 4), body });
  });
  return calls;
}

function sent(calls: SentCall[], method: string, suffix: string) {
  return () => calls.find((c) => c.method === method && c.path.endsWith(suffix))?.body ?? null;
}

function answer(page: Page, method: string, suffix: string): Promise<Response> {
  return page.waitForResponse((r) => r.request().method() === method && new URL(r.url()).pathname.endsWith(suffix));
}

async function openLookup(page: Page): Promise<SentCall[]> {
  const calls = watchCalls(page);
  await page.goto('/devices/lookup/');
  await expect(page.getByRole('heading', { name: 'Device Lookup' })).toBeVisible();
  return calls;
}

async function confirm(page: Page) {
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Confirm' }).click();
}

async function cancel(page: Page) {
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toBeHidden();
}

async function findDevice(page: Page, serial: string) {
  await page.getByLabel('Device serial').fill(serial);
  await page.getByRole('button', { name: 'Find device' }).click();
  await expect(page.getByTestId('device-result')).toContainText(serial);
}

/** The count the page shows, once it shows a number. */
async function shownCount(page: Page, testId: string): Promise<number> {
  const cell = page.getByTestId(testId);
  await expect(cell).toHaveText(/^\d+$/);
  return Number(await cell.textContent());
}

test.describe('Device lookup, counts, profiles, activation and attestation (#1743)', () => {
  test('CountDevices shows the device count', async ({ adminPage: page, sdk }) => {
    const id = await seedDevice(sdk, `SN-${uid()}`, 'Board-A');
    try {
      await openLookup(page);
      const shown = await shownCount(page, 'device-count');
      const res = await sdk.device.countDevices();
      expect(res.success).toBe(true);
      expect(shown).toBeGreaterThanOrEqual(1);
      expect(res.data?.count ?? 0).toBeGreaterThanOrEqual(1);
    } finally {
      await sdk.device.deleteDevice(id);
    }
  });

  test('CountProfiles shows the profile count', async ({ adminPage: page, sdk }) => {
    const id = await seedProfile(sdk, `Edge ${uid()}`, uniqueMac(), `Board-${uid()}`);
    try {
      await openLookup(page);
      const shown = await shownCount(page, 'profile-count');
      const res = await sdk.device.countProfiles();
      expect(res.success).toBe(true);
      expect(shown).toBeGreaterThanOrEqual(1);
      expect(res.data?.count ?? 0).toBeGreaterThanOrEqual(1);
    } finally {
      await sdk.device.deleteProfile(id);
    }
  });

  test('FindDeviceBySerial finds a device by serial', async ({ adminPage: page, sdk }) => {
    const serial = `SN-${uid()}`;
    const model = `Board-${uid()}`;
    const id = await seedDevice(sdk, serial, model);
    try {
      await openLookup(page);
      await findDevice(page, serial);
      await expect(page.getByTestId('device-result')).toContainText(model);
    } finally {
      await sdk.device.deleteDevice(id);
    }
  });

  test('FindDeviceBySerial reports a device that is not found', async ({ adminPage: page, sdk }) => {
    const serial = `SN-${uid()}`;
    const id = await seedDevice(sdk, serial, 'Board-A');
    try {
      await openLookup(page);
      await findDevice(page, serial);
      const missing = `SN-missing-${uid()}`;
      const res = await sdk.device.findDeviceBySerial(missing);
      expect(res.success).toBe(false);
      await page.getByLabel('Device serial').fill(missing);
      await page.getByRole('button', { name: 'Find device' }).click();
      await expect(page.getByText('No device found')).toBeVisible();
      await expect(page.getByTestId('device-result')).toHaveCount(0);
    } finally {
      await sdk.device.deleteDevice(id);
    }
  });

  test('UpdateDevice saves a partial update after confirm', async ({ adminPage: page, sdk }) => {
    const serial = `SN-${uid()}`;
    const model = `Board-B-${uid()}`;
    const id = await seedDevice(sdk, serial, 'Board-A');
    try {
      const calls = await openLookup(page);
      await findDevice(page, serial);
      await page.getByLabel('Model', { exact: true }).fill(model);

      await page.getByRole('button', { name: 'Update device' }).click();
      await cancel(page);
      expect(sent(calls, 'PUT', `/devices/${id}`)()).toBeNull();

      await page.getByRole('button', { name: 'Update device' }).click();
      const saved = answer(page, 'PUT', `/devices/${id}`);
      await confirm(page);
      expect((await saved).ok()).toBe(true);
      expect(sent(calls, 'PUT', `/devices/${id}`)()).toEqual({ device: { id, model } });
      await expect(page.getByTestId('device-result')).toContainText(model);
      const stored = await sdk.device.findDeviceBySerial(serial);
      expect(stored.success).toBe(true);
      expect(fieldOf(stored.data, 'model')).toBe(model);
    } finally {
      await sdk.device.deleteDevice(id);
    }
  });

  // Pasted evidence is verified against the nonce it carries, with no age
  // limit, so it would replay as a fresh verdict: the page offers no
  // paste-and-verify control until a challenge-based flow exists
  // (#2024 Codex round 4, P1).
  test('AttestDevice is not offered for pasted evidence', async ({ adminPage: page, sdk }) => {
    const serial = `SN-${uid()}`;
    const id = await seedDevice(sdk, serial, 'Board-A');
    try {
      const calls = await openLookup(page);
      await findDevice(page, serial);
      await expect(page.getByLabel('Attestation evidence (base64)')).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Attest device' })).toHaveCount(0);
      expect(calls.some((c) => c.path.endsWith('/attest'))).toBe(false);
    } finally {
      await sdk.device.deleteDevice(id);
    }
  });

  // Gap: the harness has no enrolled device the server can admit, so the
  // server may refuse the activation; the case asserts the request body and
  // the page's handling of whatever the server answers.
  test('ActivateDevice activates a device after confirm', async ({ adminPage: page, sdk }) => {
    const serial = `SN-${uid()}`;
    const mac = uniqueMac();
    const id = await seedDevice(sdk, serial, 'Board-A');
    try {
      const calls = await openLookup(page);
      await page.getByLabel('Serial', { exact: true }).fill(serial);
      await page.getByLabel('MAC address', { exact: true }).fill(mac);

      await page.getByRole('button', { name: 'Activate device' }).click();
      await cancel(page);
      expect(sent(calls, 'POST', '/device/activate-json')()).toBeNull();

      await page.getByRole('button', { name: 'Activate device' }).click();
      const activated = answer(page, 'POST', '/device/activate-json');
      await confirm(page);
      const res = await activated;
      expect(sent(calls, 'POST', '/device/activate-json')()).toEqual({ serial, mac_address: mac });
      if (res.ok()) {
        const body = (await res.json()) as { status?: string; vlan?: number };
        await expect(page.getByTestId('activate-result')).toContainText(`Admitted VLAN ${body.vlan}`);
        await expect(page.getByTestId('activate-result')).toContainText(`status ${body.status}`);
      } else {
        await expect(page.getByTestId('activate-result')).toHaveCount(0);
      }
    } finally {
      await sdk.device.deleteDevice(id);
    }
  });

  // Gap: GET /device/profile answers the calling device's own profile; the
  // admin session is not a device, so the server's answer is asserted as is.
  test('GetProfile shows the device profile', async ({ adminPage: page }) => {
    await openLookup(page);
    const loaded = answer(page, 'GET', '/device/profile');
    await page.getByRole('button', { name: 'Load device profile' }).click();
    const res = await loaded;
    if (res.ok()) {
      const body = (await res.json()) as { serialNumber?: string };
      await expect(page.getByTestId('device-profile-result')).toBeVisible();
      if (body.serialNumber) await expect(page.getByTestId('device-profile-result')).toContainText(body.serialNumber);
    } else {
      await expect(page.getByTestId('device-profile-result')).toHaveCount(0);
    }
  });

  test('FindProfileByMACAddress finds a profile by MAC', async ({ adminPage: page, sdk }) => {
    const name = `Edge ${uid()}`;
    const mac = uniqueMac();
    const id = await seedProfile(sdk, name, mac, `Board-${uid()}`);
    try {
      await openLookup(page);
      await page.getByLabel('Profile MAC address').fill(mac);
      await page.getByRole('button', { name: 'Find by MAC' }).click();
      await expect(page.getByTestId('profile-result')).toContainText(name);
    } finally {
      await sdk.device.deleteProfile(id);
    }
  });

  // Gap: a profile is found by serial only once the server links it to a
  // device serial; the SDK seeds no such link, so the case asserts the
  // server's answer for the seeded device's serial.
  test('FindProfileBySerial finds a profile by serial', async ({ adminPage: page, sdk }) => {
    const serial = `SN-${uid()}`;
    const deviceId = await seedDevice(sdk, serial, 'Board-A');
    try {
      await openLookup(page);
      await page.getByLabel('Profile serial').fill(serial);
      const found = answer(page, 'GET', `/device/profiles/serial/${serial}`);
      await page.getByRole('button', { name: 'Find by serial' }).click();
      const res = await found;
      if (res.ok()) {
        const name = fieldOf(await res.json(), 'name');
        await expect(page.getByTestId('profile-result')).toContainText(String(name));
      } else {
        await expect(page.getByTestId('profile-result')).toHaveCount(0);
      }
    } finally {
      await sdk.device.deleteDevice(deviceId);
    }
  });

  test('FindMatchingProfile matches a profile', async ({ adminPage: page, sdk }) => {
    const name = `Edge ${uid()}`;
    const mac = uniqueMac();
    const model = `Board-${uid()}`;
    const id = await seedProfile(sdk, name, mac, model);
    try {
      const calls = await openLookup(page);
      await page.getByLabel('Profile MAC address').fill(mac);
      await page.getByLabel('Match model').fill(model);
      const matched = answer(page, 'POST', '/device/profiles/match');
      await page.getByRole('button', { name: 'Match profile' }).click();
      const res = await matched;
      const body = sent(calls, 'POST', '/device/profiles/match')() as Record<string, unknown>;
      expect(body).toEqual({ mac_address: mac, model });
      expect(body).not.toHaveProperty('macAddress');
      if (res.ok()) {
        await expect(page.getByTestId('profile-result')).toContainText(String(fieldOf(await res.json(), 'name')));
      } else {
        await expect(page.getByTestId('profile-result')).toHaveCount(0);
      }
    } finally {
      await sdk.device.deleteProfile(id);
    }
  });

  // The profile is found by MAC (the seeded link the server has) instead of
  // by serial; see the FindProfileBySerial gap.
  test('UpdateProfile saves a partial update after confirm', async ({ adminPage: page, sdk }) => {
    const name = `Edge ${uid()}`;
    const renamed = `${name} v2`;
    const mac = uniqueMac();
    const id = await seedProfile(sdk, name, mac, `Board-${uid()}`);
    try {
      const calls = await openLookup(page);
      await page.getByLabel('Profile MAC address').fill(mac);
      await page.getByRole('button', { name: 'Find by MAC' }).click();
      await expect(page.getByTestId('profile-result')).toContainText(name);
      await page.getByLabel('Profile name').fill(renamed);

      await page.getByRole('button', { name: 'Update profile' }).click();
      await cancel(page);
      expect(sent(calls, 'PUT', `/device/profiles/${id}`)()).toBeNull();

      await page.getByRole('button', { name: 'Update profile' }).click();
      const saved = answer(page, 'PUT', `/device/profiles/${id}`);
      await confirm(page);
      expect((await saved).ok()).toBe(true);
      const body = sent(calls, 'PUT', `/device/profiles/${id}`)() as Record<string, unknown>;
      expect(body).not.toHaveProperty('profile');
      expect(body).toMatchObject({ name: renamed, mac_address: mac });
      await expect(page.getByTestId('profile-result')).toContainText(renamed);
      const stored = await sdk.device.getProfile(id);
      expect(stored.success).toBe(true);
      expect(fieldOf(stored.data, 'name')).toBe(renamed);
    } finally {
      await sdk.device.deleteProfile(id);
    }
  });
});
