import { test, expect } from './fixtures';
import type { Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';

/**
 * Device lookup page (/devices/lookup/) against the real server.
 *
 * Ported from web/e2e/device-lookup.spec.ts (#2036, epic #1665, ruling 972).
 * Each test seeds its own devices and profiles (unique serial, model and a
 * locally administered MAC) through sdk.device.createDevice and
 * sdk.device.createProfile, reads the expected answer from the server through
 * the SDK first, drives the page, waits for the page's own request, and checks
 * that the page shows what the server answered: the value when the server
 * found it, the page's empty or refused state when it did not. Whatever a test
 * creates is deleted in afterEach. Mocked cases with no server behind them
 * (canned counts, a device-side GetProfile with an admin session, a canned
 * activation VLAN) are listed as gaps in the PR body.
 */

const unique = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6)}`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function must<T>(res: { success: boolean; data?: T; error?: any }, what: string): T {
  if (!res.success || res.data === undefined) {
    throw new Error(`${what} failed: ${JSON.stringify(res.error)}`);
  }
  return res.data;
}

/** A unique locally administered MAC, 02:00:00:xx:xx:xx. */
function uniqueMAC(): string {
  const byte = () =>
    Math.floor(Math.random() * 256)
      .toString(16)
      .padStart(2, '0');
  return `02:00:00:${byte()}:${byte()}:${byte()}`;
}

interface CreatedDevice {
  id: string;
  model: string;
  serial: string;
}

interface CreatedProfile {
  id: string;
  name: string;
  model: string;
  serial: string;
  mac: string;
}

const createdDevices: string[] = [];
const createdProfiles: string[] = [];

async function newDevice(sdk: PlatformClient, prefix: string): Promise<CreatedDevice> {
  const model = unique(prefix);
  const serial = unique(`SN-${prefix}`);
  const res = must(
    await sdk.device.createDevice({ device: { model, serial, hash_algo_id: 11 } }),
    'device.createDevice',
  ) as { device?: { id: string } };
  const id = res.device?.id;
  if (!id) throw new Error(`device.createDevice(${serial}) answered no device id`);
  createdDevices.push(id);
  return { id, model, serial };
}

async function newProfile(sdk: PlatformClient, prefix: string): Promise<CreatedProfile> {
  const name = unique(`${prefix} profile`);
  const model = unique(prefix);
  const serial = unique(`EK-${prefix}`);
  const mac = uniqueMAC();
  const res = must(
    await sdk.device.createProfile({
      profile: { name, model, role: 'server', ek_serial: serial, mac_address: mac },
    }),
    'device.createProfile',
  ) as { profile?: { id: string }; id?: string };
  const id = res.profile?.id ?? res.id;
  if (!id) throw new Error(`device.createProfile(${name}) answered no profile id`);
  createdProfiles.push(id);
  return { id, name, model, serial, mac };
}

/** Resolves with the page's next response whose method and path match. */
function answered(page: Page, method: string, path: string | RegExp): Promise<Response> {
  return page.waitForResponse((r) => {
    if (r.request().method() !== method) return false;
    const pathname = new URL(r.url()).pathname;
    return typeof path === 'string' ? pathname.endsWith(path) : path.test(pathname);
  });
}

async function openLookup(page: Page): Promise<void> {
  await page.goto('/devices/lookup/');
  await expect(page.getByRole('heading', { name: 'Device Lookup' })).toBeVisible();
}

async function confirm(page: Page): Promise<void> {
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Confirm' }).click();
}

async function cancel(page: Page): Promise<void> {
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toBeHidden();
}

async function findDevice(page: Page, serial: string): Promise<Response> {
  await page.getByLabel('Device serial').fill(serial);
  const res = answered(page, 'GET', `/devices/serial/${encodeURIComponent(serial)}`);
  await page.getByRole('button', { name: 'Find device' }).click();
  return res;
}

test.afterEach(async ({ sdk }) => {
  while (createdProfiles.length > 0) {
    await sdk.device.deleteProfile(createdProfiles.pop() as string);
  }
  while (createdDevices.length > 0) {
    await sdk.device.deleteDevice(createdDevices.pop() as string);
  }
});

test.describe('Device lookup on the real server: counts, profiles, activation and attestation (#2036)', () => {
  test('CountDevices shows the device count the server answers', async ({ adminPage: page, sdk }) => {
    await newDevice(sdk, 'count');
    const want = must(await sdk.device.countDevices(), 'device.countDevices').count;
    expect(want).toBeGreaterThan(0);

    const res = answered(page, 'GET', '/devices/count');
    await openLookup(page);
    expect((await res).ok()).toBe(true);
    await expect(page.getByTestId('device-count')).toHaveText(String(want));
  });

  test('CountProfiles shows the profile count the server answers', async ({ adminPage: page, sdk }) => {
    await newProfile(sdk, 'count');
    const want = must(await sdk.device.countProfiles(), 'device.countProfiles').count;
    expect(want).toBeGreaterThan(0);

    const res = answered(page, 'GET', '/device/profiles/count');
    await openLookup(page);
    expect((await res).ok()).toBe(true);
    await expect(page.getByTestId('profile-count')).toHaveText(String(want));
  });

  test('FindDeviceBySerial finds a seeded device by serial', async ({ adminPage: page, sdk }) => {
    const device = await newDevice(sdk, 'find');
    const want = must(await sdk.device.findDeviceBySerial(device.serial), 'device.findDeviceBySerial');
    expect(want.id).toBe(device.id);

    await openLookup(page);
    expect((await findDevice(page, device.serial)).ok()).toBe(true);
    const result = page.getByTestId('device-result');
    await expect(result).toContainText(device.serial);
    await expect(result).toContainText(device.model);
  });

  test('FindDeviceBySerial reports a device the server does not find', async ({ adminPage: page, sdk }) => {
    const device = await newDevice(sdk, 'missing');
    const absent = unique('SN-absent');
    expect((await sdk.device.findDeviceBySerial(absent)).success).toBe(false);

    await openLookup(page);
    await findDevice(page, device.serial);
    await expect(page.getByTestId('device-result')).toContainText(device.serial);

    expect((await findDevice(page, absent)).ok()).toBe(false);
    await expect(page.getByText('No device found')).toBeVisible();
    await expect(page.getByTestId('device-result')).toHaveCount(0);
  });

  test('UpdateDevice saves the model after confirm, and not after cancel', async ({ adminPage: page, sdk }) => {
    const device = await newDevice(sdk, 'update');
    const model = unique('updated');

    await openLookup(page);
    await findDevice(page, device.serial);
    await expect(page.getByTestId('device-result')).toContainText(device.serial);
    await page.getByLabel('Model', { exact: true }).fill(model);

    await page.getByRole('button', { name: 'Update device' }).click();
    await cancel(page);
    const kept = must(await sdk.device.findDeviceBySerial(device.serial), 'device.findDeviceBySerial');
    expect(kept.model).toBe(device.model);

    await page.getByRole('button', { name: 'Update device' }).click();
    const res = answered(page, 'PUT', `/devices/${device.id}`);
    await confirm(page);
    expect((await res).ok()).toBe(true);
    await expect(page.getByTestId('device-result')).toContainText(model);

    const saved = must(await sdk.device.findDeviceBySerial(device.serial), 'device.findDeviceBySerial');
    expect(saved.model).toBe(model);
    expect(saved.serial).toBe(device.serial);
  });

  // Pasted evidence is verified against the nonce it carries, with no age
  // limit, so it would replay as a fresh verdict: the page offers no
  // paste-and-verify control until a challenge-based flow exists
  // (#2024 Codex round 4, P1).
  test('AttestDevice is not offered for pasted evidence', async ({ adminPage: page, sdk }) => {
    const device = await newDevice(sdk, 'attest');
    const attestCalls: string[] = [];
    page.on('request', (r) => {
      if (new URL(r.url()).pathname.endsWith('/attest')) attestCalls.push(r.url());
    });

    await openLookup(page);
    await findDevice(page, device.serial);
    await expect(page.getByTestId('device-result')).toContainText(device.serial);
    await expect(page.getByLabel('Attestation evidence (base64)')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Attest device' })).toHaveCount(0);
    expect(attestCalls).toEqual([]);
  });

  test('ActivateDevice shows the server answer after confirm, and asks nothing after cancel', async ({
    adminPage: page,
    sdk,
  }) => {
    const device = await newDevice(sdk, 'activate');
    const mac = uniqueMAC();
    // Activation resolves the admitted VLAN and programs no switch, so the
    // SDK call first reads the answer the page must show.
    const want = await sdk.device.activateDevice({ serial: device.serial, macAddress: mac });
    const activateCalls: string[] = [];
    page.on('request', (r) => {
      if (new URL(r.url()).pathname.endsWith('/device/activate-json')) activateCalls.push(r.method());
    });

    await openLookup(page);
    await page.getByLabel('Serial', { exact: true }).fill(device.serial);
    await page.getByLabel('MAC address', { exact: true }).fill(mac);

    await page.getByRole('button', { name: 'Activate device' }).click();
    await cancel(page);
    expect(activateCalls).toEqual([]);

    await page.getByRole('button', { name: 'Activate device' }).click();
    const res = answered(page, 'POST', '/device/activate-json');
    await confirm(page);
    const response = await res;
    expect(response.ok()).toBe(want.success);

    if (want.success && want.data) {
      const vlan = want.data.vlan !== undefined ? `Admitted VLAN ${want.data.vlan}` : 'No admitted VLAN';
      await expect(page.getByTestId('activate-result')).toHaveText(
        `${vlan} (status ${want.data.status}; switch not changed)`,
      );
    } else {
      await expect(page.getByText('Activation failed').first()).toBeVisible();
      await expect(page.getByTestId('activate-result')).toHaveCount(0);
    }

    // The device record is still there, unchanged by the lookup.
    const after = must(await sdk.device.findDeviceBySerial(device.serial), 'device.findDeviceBySerial');
    expect(after.id).toBe(device.id);
    expect(after.model).toBe(device.model);
  });

  test('GetProfile shows what the server answers for the calling session', async ({ adminPage: page, sdk }) => {
    // The route resolves the calling device from its client certificate; the
    // admin session has none, so the server's answer here is read first.
    const want = await sdk.device.getDeviceProfile();

    await openLookup(page);
    const res = answered(page, 'GET', /\/device\/profile$/);
    await page.getByRole('button', { name: 'Load device profile' }).click();
    expect((await res).ok()).toBe(want.success);

    if (want.success && want.data) {
      const result = page.getByTestId('device-profile-result');
      await expect(result).toContainText(String(want.data.serialNumber));
      await expect(result).toContainText(JSON.stringify(want.data.admittedNetwork));
    } else {
      await expect(page.getByText('Device profile failed').first()).toBeVisible();
      await expect(page.getByTestId('device-profile-result')).toHaveCount(0);
    }
  });

  test('FindProfileByMACAddress finds a seeded profile by MAC', async ({ adminPage: page, sdk }) => {
    const profile = await newProfile(sdk, 'mac');
    const want = must(await sdk.device.findProfileByMACAddress(profile.mac), 'device.findProfileByMACAddress');
    expect(want.id).toBe(profile.id);

    await openLookup(page);
    await page.getByLabel('Profile MAC address').fill(profile.mac);
    const res = answered(page, 'GET', `/device/profiles/mac/${encodeURIComponent(profile.mac)}`);
    await page.getByRole('button', { name: 'Find by MAC' }).click();
    expect((await res).ok()).toBe(true);
    await expect(page.getByTestId('profile-result')).toContainText(profile.name);
  });

  test('FindProfileBySerial shows what the server answers for a seeded serial', async ({ adminPage: page, sdk }) => {
    const profile = await newProfile(sdk, 'serial');
    const want = await sdk.device.findProfileBySerial(profile.serial);

    await openLookup(page);
    await page.getByLabel('Profile serial').fill(profile.serial);
    const res = answered(page, 'GET', `/device/profiles/serial/${encodeURIComponent(profile.serial)}`);
    await page.getByRole('button', { name: 'Find by serial' }).click();
    expect((await res).ok()).toBe(want.success);

    if (want.success && want.data) {
      expect(want.data.id).toBe(profile.id);
      await expect(page.getByTestId('profile-result')).toContainText(profile.name);
    } else {
      await expect(page.getByText('No profile found')).toBeVisible();
      await expect(page.getByTestId('profile-result')).toHaveCount(0);
    }
  });

  test('FindMatchingProfile shows the profile the server matches', async ({ adminPage: page, sdk }) => {
    const profile = await newProfile(sdk, 'match');
    const want = await sdk.device.findMatchingProfile({ macAddress: profile.mac, model: profile.model });

    await openLookup(page);
    await page.getByLabel('Profile MAC address').fill(profile.mac);
    await page.getByLabel('Match model').fill(profile.model);
    const res = answered(page, 'POST', '/device/profiles/match');
    await page.getByRole('button', { name: 'Match profile' }).click();
    const response = await res;
    expect(response.ok()).toBe(want.success);
    expect(response.request().postDataJSON()).toEqual({ mac_address: profile.mac, model: profile.model });

    if (want.success && want.data) {
      await expect(page.getByTestId('profile-result')).toContainText(want.data.name);
    } else {
      await expect(page.getByText('No profile found')).toBeVisible();
      await expect(page.getByTestId('profile-result')).toHaveCount(0);
    }
  });

  test('UpdateProfile saves the name after confirm, and not after cancel', async ({ adminPage: page, sdk }) => {
    const profile = await newProfile(sdk, 'update');
    const name = unique('renamed profile');

    await openLookup(page);
    await page.getByLabel('Profile MAC address').fill(profile.mac);
    await page.getByRole('button', { name: 'Find by MAC' }).click();
    await expect(page.getByTestId('profile-result')).toContainText(profile.name);
    await page.getByLabel('Profile name').fill(name);

    await page.getByRole('button', { name: 'Update profile' }).click();
    await cancel(page);
    const kept = must(await sdk.device.getProfile(profile.id), 'device.getProfile') as unknown as {
      profile?: { name: string };
      name?: string;
    };
    expect(kept.profile?.name ?? kept.name).toBe(profile.name);

    await page.getByRole('button', { name: 'Update profile' }).click();
    const res = answered(page, 'PUT', `/device/profiles/${profile.id}`);
    await confirm(page);
    const response = await res;
    expect(response.ok()).toBe(true);
    const body = response.request().postDataJSON() as Record<string, unknown>;
    expect(body).not.toHaveProperty('profile');
    expect(body).toMatchObject({ name, mac_address: profile.mac, ek_serial: profile.serial });
    await expect(page.getByTestId('profile-result')).toContainText(name);

    const saved = must(await sdk.device.getProfile(profile.id), 'device.getProfile') as unknown as {
      profile?: { name: string; mac_address?: string; ek_serial?: string };
      name?: string;
      mac_address?: string;
      ek_serial?: string;
    };
    const stored = saved.profile ?? saved;
    expect(stored.name).toBe(name);
    expect(stored.mac_address).toBe(profile.mac);
    expect(stored.ek_serial).toBe(profile.serial);
  });
});
