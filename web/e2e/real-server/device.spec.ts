import type { Page } from '@playwright/test';
import { test as base, expect } from '@playwright/test';
import { PlatformClient } from 'trusted-platform-sdk';

type Fx = { adminPage: Page; sdk: PlatformClient };

const apiUrl = process.env.E2E_REAL_SERVER_API_URL ?? '';
const adminJwt = process.env.E2E_REAL_SERVER_ADMIN_JWT ?? '';

const test = base.extend<Fx>({
  sdk: async ({}, provide, testInfo) => {
    testInfo.skip(!apiUrl || !adminJwt, 'real server not configured (E2E_REAL_SERVER_API_URL, E2E_REAL_SERVER_ADMIN_JWT)');
    await provide(new PlatformClient({ baseUrl: apiUrl, headers: { Authorization: `Bearer ${adminJwt}` } }));
  },
  adminPage: async ({ page, context, baseURL }, provide, testInfo) => {
    testInfo.skip(!apiUrl || !adminJwt, 'real server not configured (E2E_REAL_SERVER_API_URL, E2E_REAL_SERVER_ADMIN_JWT)');
    const domain = new URL(baseURL ?? 'http://localhost:3000').hostname;
    await context.addCookies([{ name: 'jwt', value: adminJwt, domain, path: '/', httpOnly: false, secure: false, sameSite: 'Lax' }]);
    await provide(page);
  },
});

// #2048, coverage-matrix slice 11: the device row's operations on
// /devices/lookup against the real server. State is seeded through the SDK
// (no route mocks) and every assertion reads what the server answered.
//
// Gated off, by design (DeviceRouteGate): AttestDevice (pasted evidence
// replays, #2024 Codex round 4 P1), GetProfile over /device/profile (needs
// the device's client certificate), BootCertificate and BootDelivery
// (machine-facing, the diskless node's own connection).

function unique(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

function macFor(seed: number): string {
  const byte = (n: number) => (n & 0xff).toString(16).padStart(2, '0');
  return `52:54:00:${byte(seed >> 16)}:${byte(seed >> 8)}:${byte(seed)}`;
}

/** The created resource, whether the server wraps it or answers it flat. */
function created<T extends { id: string }>(data: unknown, key: string): T {
  const body = data as Record<string, unknown> | undefined;
  const wrapped = body?.[key] as T | undefined;
  return wrapped ?? (body as unknown as T);
}

test.describe('device operations (real server)', () => {
  test('shows the device and profile counts the server reports', async ({ adminPage, sdk }) => {
    const devices = await sdk.device.countDevices();
    const profiles = await sdk.device.countProfiles();
    expect(devices.success).toBe(true);
    expect(profiles.success).toBe(true);

    await adminPage.goto('/devices/lookup');

    await expect(adminPage.getByTestId('device-count')).toHaveText(String(devices.data?.count));
    await expect(adminPage.getByTestId('profile-count')).toHaveText(String(profiles.data?.count));
  });

  test('finds a seeded device by serial and saves its model', async ({ adminPage, sdk }) => {
    const serial = unique('SN-dev');
    const create = await sdk.device.createDevice({ device: { serial, model: 'Board-A' } });
    expect(create.success).toBe(true);

    await adminPage.goto('/devices/lookup');
    await adminPage.getByLabel('Device serial').fill(serial);
    await adminPage.getByRole('button', { name: 'Find device' }).click();
    await adminPage.getByLabel('Model', { exact: true }).fill('Board-B');
    await adminPage.getByRole('button', { name: 'Update device' }).click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    await expect(adminPage.getByText('Device updated').first()).toBeVisible();

    const after = await sdk.device.findDeviceBySerial(serial);
    expect(after.success).toBe(true);
    expect(after.data?.model).toBe('Board-B');
  });

  test('finds a seeded profile by ID, MAC, serial and match, and renames it', async ({ adminPage, sdk }) => {
    const serial = unique('SN-prof');
    const mac = macFor(Date.now());
    const name = unique('profile');
    const create = await sdk.device.createProfile({
      profile: { name, model: 'Board-A', role: 'worker', ek_serial: serial, mac_address: mac },
    });
    expect(create.success).toBe(true);
    const profile = created<{ id: string }>(create.data, 'profile');

    await adminPage.goto('/devices/lookup');
    const nameField = adminPage.getByLabel('Profile name');

    await adminPage.getByLabel('Profile ID').fill(String(profile.id));
    await adminPage.getByRole('button', { name: 'Find by ID' }).click();
    await expect(nameField).toHaveValue(name);

    await adminPage.getByLabel('Profile MAC address').fill(mac);
    await adminPage.getByRole('button', { name: 'Find by MAC' }).click();
    await expect(nameField).toHaveValue(name);

    await adminPage.getByLabel('Profile serial').fill(serial);
    await adminPage.getByRole('button', { name: 'Find by serial' }).click();
    await expect(nameField).toHaveValue(name);

    await adminPage.getByRole('button', { name: 'Match profile' }).click();
    await expect(nameField).toHaveValue(name);

    const renamed = `${name}-renamed`;
    await nameField.fill(renamed);
    await adminPage.getByRole('button', { name: 'Update profile' }).click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    await expect(adminPage.getByText('Profile updated').first()).toBeVisible();

    const after = await sdk.device.getProfile(String(profile.id));
    expect(after.success).toBe(true);
    expect(created<{ id: string; name: string }>(after.data, 'profile').name).toBe(renamed);
  });

  test('activation answers the admitted VLAN the server resolves', async ({ adminPage, sdk }) => {
    const serial = unique('SN-act');
    const mac = macFor(Date.now() + 1);
    expect((await sdk.device.createDevice({ device: { serial, model: 'Board-A' } })).success).toBe(true);
    expect(
      (
        await sdk.device.createProfile({
          profile: { name: unique('act'), model: 'Board-A', role: 'worker', ek_serial: serial, mac_address: mac },
        })
      ).success
    ).toBe(true);
    const expected = await sdk.device.activateDevice({ serial, macAddress: mac });

    await adminPage.goto('/devices/lookup');
    await adminPage.getByLabel('Serial', { exact: true }).fill(serial);
    await adminPage.getByLabel('MAC address', { exact: true }).fill(mac);
    await adminPage.getByRole('button', { name: 'Activate device' }).click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();

    if (expected.success) {
      const vlan = expected.data?.vlan;
      await expect(adminPage.getByTestId('activate-result')).toContainText(
        vlan !== undefined ? `Admitted VLAN ${vlan}` : 'No admitted VLAN'
      );
    } else {
      await expect(adminPage.getByText('Activation failed').first()).toBeVisible();
    }
  });

  test('machine-facing and replayable operations are gated off with their reason', async ({ adminPage }) => {
    await adminPage.goto('/devices/lookup');

    for (const [name, operation] of [
      ['Verify attestation', 'AttestDevice'],
      ['Load device profile', 'GetProfile'],
      ['Fetch boot certificate', 'BootCertificate'],
      ['Request boot delivery', 'BootDelivery'],
    ] as const) {
      await expect(adminPage.getByRole('button', { name })).toBeDisabled();
      await expect(adminPage.getByTestId(`device-gate-${operation}`)).not.toBeEmpty();
    }
  });
});
