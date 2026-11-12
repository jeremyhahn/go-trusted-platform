import { test, expect, Page } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockTenantApi, mockDeviceLookupApi } from './fixtures/api-mock';
import type { DeviceLookupCall, DeviceLookupMockConfig } from './fixtures/api-mock';

const DEVICE = { id: '5', serial: 'SN-1', model: 'Board-A', hash_algo_id: 11 };
const PROFILE = { id: '3', name: 'Edge nodes', model: 'Board-A', role: 'server' };
const OK = { success: true, message: 'ok' };

const COUNTS: DeviceLookupMockConfig = {
  'GET /devices/count': { count: 42 },
  'GET /device/profiles/count': { count: 7 },
};

async function openLookup(page: Page, config: DeviceLookupMockConfig = {}): Promise<DeviceLookupCall[]> {
  await mockTenantApi(page);
  const calls = await mockDeviceLookupApi(page, { ...COUNTS, ...config });
  await page.goto('/devices/lookup/');
  await expect(page.getByRole('heading', { name: 'Device Lookup' })).toBeVisible();
  return calls;
}

function call(calls: DeviceLookupCall[], method: string, path: string) {
  return () => calls.find((c) => c.method === method && c.path === path)?.body ?? null;
}

async function confirm(page: Page) {
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Confirm' }).click();
}

async function findDevice(page: Page) {
  await page.getByLabel('Device serial').fill('SN-1');
  await page.getByRole('button', { name: 'Find device' }).click();
  await expect(page.getByTestId('device-result')).toContainText('SN-1');
}

const FIND_DEVICE: DeviceLookupMockConfig = { 'GET /devices/serial/SN-1': { device: DEVICE } };

test.describe('Device lookup, counts, profiles, activation and attestation (#1743)', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('CountDevices shows the device count', async ({ page }) => {
    await openLookup(page);
    await expect(page.getByTestId('device-count')).toHaveText('42');
  });

  test('CountProfiles shows the profile count', async ({ page }) => {
    await openLookup(page);
    await expect(page.getByTestId('profile-count')).toHaveText('7');
  });

  test('FindDeviceBySerial finds a device by serial', async ({ page }) => {
    await openLookup(page, FIND_DEVICE);
    await findDevice(page);
    await expect(page.getByTestId('device-result')).toContainText('Board-A');
  });

  test('FindDeviceBySerial reports a device that is not found', async ({ page }) => {
    await openLookup(page, { 'GET /devices/serial/SN-9': { status: 404, error: 'device not found' } });
    await page.getByLabel('Device serial').fill('SN-9');
    await page.getByRole('button', { name: 'Find device' }).click();
    await expect(page.getByText('No device found')).toBeVisible();
  });

  test('UpdateDevice saves a partial update after confirm', async ({ page }) => {
    const calls = await openLookup(page, {
      ...FIND_DEVICE,
      'PUT /devices/5': { status: OK, device: { ...DEVICE, model: 'Board-B' } },
    });
    await findDevice(page);
    await page.getByLabel('Model', { exact: true }).fill('Board-B');

    await page.getByRole('button', { name: 'Update device' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
    expect(call(calls, 'PUT', '/devices/5')()).toBeNull();

    await page.getByRole('button', { name: 'Update device' }).click();
    await confirm(page);
    await expect.poll(call(calls, 'PUT', '/devices/5')).toEqual({ device: { id: '5', model: 'Board-B' } });
    await expect(page.getByTestId('device-result')).toContainText('Board-B');
  });

  test('AttestDevice attests a device after confirm', async ({ page }) => {
    const calls = await openLookup(page, {
      ...FIND_DEVICE,
      'POST /devices/5/attest': {
        device_id: '5',
        verified: true,
        signature_valid: true,
        nonce_valid: true,
        pcrs_valid: true,
        attestation_status: 'trusted',
        attested_at: '2026-11-12T00:00:00Z',
      },
    });
    await findDevice(page);
    await page.getByLabel('Attestation evidence (base64)').fill('ZXZpZGVuY2U=');
    await page.getByRole('button', { name: 'Attest device' }).click();
    await confirm(page);
    await expect.poll(call(calls, 'POST', '/devices/5/attest')).toEqual({ evidence: 'ZXZpZGVuY2U=' });
    await expect(page.getByTestId('attest-result')).toHaveText('Verified: trusted');
  });

  test('ActivateDevice activates a device after confirm', async ({ page }) => {
    const calls = await openLookup(page, {
      'POST /device/activate-json': { status: OK, activationStatus: 'activated', vlan: 20 },
    });
    await page.getByLabel('Serial', { exact: true }).fill('SN-1');
    await page.getByLabel('MAC address', { exact: true }).fill('aa:bb:cc:dd:ee:ff');
    await page.getByRole('button', { name: 'Activate device' }).click();
    await confirm(page);
    await expect
      .poll(call(calls, 'POST', '/device/activate-json'))
      .toEqual({ serial: 'SN-1', macAddress: 'aa:bb:cc:dd:ee:ff' });
    await expect(page.getByTestId('activate-result')).toHaveText('activated (VLAN 20)');
  });

  test('GetProfile shows the device profile', async ({ page }) => {
    await openLookup(page, {
      'GET /device/profile': { serialNumber: 'SN-1', admittedNetwork: { name: 'trusted', vlan: 20 } },
    });
    await page.getByRole('button', { name: 'Load device profile' }).click();
    await expect(page.getByTestId('device-profile-result')).toContainText('SN-1');
    await expect(page.getByTestId('device-profile-result')).toContainText('trusted');
  });

  test('FindProfileByMACAddress finds a profile by MAC', async ({ page }) => {
    await openLookup(page, { 'GET /device/profiles/mac/aa:bb:cc:dd:ee:ff': { profile: PROFILE } });
    await page.getByLabel('Profile MAC address').fill('aa:bb:cc:dd:ee:ff');
    await page.getByRole('button', { name: 'Find by MAC' }).click();
    await expect(page.getByTestId('profile-result')).toContainText('Edge nodes');
  });

  test('FindProfileBySerial finds a profile by serial', async ({ page }) => {
    await openLookup(page, { 'GET /device/profiles/serial/SN-1': { profile: PROFILE } });
    await page.getByLabel('Profile serial').fill('SN-1');
    await page.getByRole('button', { name: 'Find by serial' }).click();
    await expect(page.getByTestId('profile-result')).toContainText('Edge nodes');
  });

  test('FindMatchingProfile matches a profile', async ({ page }) => {
    const calls = await openLookup(page, { 'POST /device/profiles/match': { profile: PROFILE } });
    await page.getByLabel('Match model').fill('Board-A');
    await page.getByRole('button', { name: 'Match profile' }).click();
    await expect(page.getByTestId('profile-result')).toContainText('Edge nodes');
    expect(call(calls, 'POST', '/device/profiles/match')()).toEqual({ model: 'Board-A' });
  });

  test('UpdateProfile saves a partial update after confirm', async ({ page }) => {
    const calls = await openLookup(page, {
      'GET /device/profiles/serial/SN-1': { profile: PROFILE },
      'PUT /device/profiles/3': { status: OK, profile: { ...PROFILE, name: 'Edge nodes v2' } },
    });
    await page.getByLabel('Profile serial').fill('SN-1');
    await page.getByRole('button', { name: 'Find by serial' }).click();
    await page.getByLabel('Profile name').fill('Edge nodes v2');
    await page.getByRole('button', { name: 'Update profile' }).click();
    await confirm(page);
    await expect
      .poll(call(calls, 'PUT', '/device/profiles/3'))
      .toEqual({ profile: { id: '3', name: 'Edge nodes v2' } });
    await expect(page.getByTestId('profile-result')).toContainText('Edge nodes v2');
  });
});
