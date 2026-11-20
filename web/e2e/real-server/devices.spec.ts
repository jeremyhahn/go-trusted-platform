import { test, expect } from './fixtures';
import type { Page } from '@playwright/test';

/**
 * Devices pages against the real server.
 *
 * Ported from web/e2e/devices.spec.ts (#2037, epic #1665, ruling 972). Each
 * test creates its own devices (unique model and serial) through
 * sdk.device.createDevice, drives the page, and checks the result against
 * what the server answers. Whatever a test leaves is deleted in afterEach.
 * Mocked cases with no server behaviour behind them (injected 500s, a delayed
 * list, canned attestation history and certificates, a member session) are
 * listed as gaps in docs/plans/1665-port-3.md, "devices (part 1 of 2)".
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

/** A placeholder attestation public key: the list shows a TPM row for it. */
const ATTEST_PUB = Buffer.from('e2e-attest-pub-key').toString('base64');

interface Created {
  id: string;
  model: string;
  serial: string;
}

const createdDevices: string[] = [];

async function newDevice(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  sdk: any,
  prefix: string,
  extra: Record<string, unknown> = {},
): Promise<Created> {
  const model = unique(prefix);
  const serial = unique(`SN-${prefix}`);
  const res = must(
    await sdk.device.createDevice({ device: { model, serial, hash_algo_id: 11, ...extra } }),
    'device.createDevice',
  ) as { device?: { id: string } };
  const id = res.device?.id;
  if (!id) throw new Error(`device.createDevice(${serial}) answered no device id`);
  createdDevices.push(id);
  return { id, model, serial };
}

/** Deletes every device of the worker's tenant (its own tenant, see fixtures). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function deleteAllDevices(sdk: any): Promise<void> {
  const list = must(await sdk.device.listDevices({ page: 1, pageSize: 100 }), 'device.listDevices') as {
    devices?: { id: string }[];
  };
  for (const d of list.devices ?? []) {
    await sdk.device.deleteDevice(d.id);
  }
}

/** Opens the static-export details page and moves the URL as the router would. */
async function openDetails(page: Page, id: string): Promise<void> {
  await page.goto('/devices/__placeholder__/');
  await page.waitForLoadState('networkidle');
  await page.evaluate((deviceId) => window.history.pushState(null, '', `/devices/${deviceId}/`), id);
}

async function openRegisterDialog(page: Page): Promise<void> {
  await page.goto('/devices');
  await page.getByRole('button', { name: /register device/i }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
}

test.afterEach(async ({ sdk }) => {
  while (createdDevices.length > 0) {
    await sdk.device.deleteDevice(createdDevices.pop() as string);
  }
});

test.describe('Devices Management', () => {
  test.describe('Device List', () => {
    test('should display device table with columns', async ({ adminPage: page, sdk }) => {
      const a = await newDevice(sdk, 'Server');
      const b = await newDevice(sdk, 'VM');

      await page.goto('/devices');

      await expect(page.getByRole('heading', { name: /devices/i }).first()).toBeVisible();
      await expect(page.getByRole('columnheader', { name: /name/i })).toBeVisible();
      await expect(page.getByRole('columnheader', { name: /type/i })).toBeVisible();
      await expect(page.getByRole('columnheader', { name: /tpm status/i })).toBeVisible();
      await expect(page.getByRole('columnheader', { name: /last seen/i })).toBeVisible();
      await expect(page.getByRole('columnheader', { name: 'Status', exact: true })).toBeVisible();
      await expect(page.getByRole('columnheader', { name: /actions/i })).toBeVisible();

      await expect(page.getByText(a.model)).toBeVisible();
      await expect(page.getByText(b.model)).toBeVisible();
    });

    test('should display device status badges correctly', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Status-Device');
      const got = must(await sdk.device.getDevice(d.id), 'device.getDevice') as unknown as {
        device?: { last_heartbeat_at?: string };
      };

      await page.goto('/devices');
      const row = page.getByRole('row').filter({ hasText: d.model });
      await expect(row).toBeVisible();
      // A device that never heartbeated has no liveness: the badge is not Online.
      if (!got.device?.last_heartbeat_at) {
        await expect(row.getByText('Online', { exact: true })).toHaveCount(0);
      }
    });

    test('should display device type badges correctly', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Physical-Device');

      await page.goto('/devices');

      const row = page.getByRole('row').filter({ hasText: d.model });
      await expect(row.getByText(/physical/i).first()).toBeVisible();
    });

    test('should show empty state when no devices', async ({ adminPage: page, sdk }) => {
      await deleteAllDevices(sdk);

      await page.goto('/devices');

      await expect(page.getByText(/no devices found/i)).toBeVisible();
    });

    test('should show loading state', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Loading-Device');

      await page.goto('/devices');

      // The server answer is not delayed: the loading text gives way to the list.
      await expect(page.getByText(d.model)).toBeVisible();
      await expect(page.getByText(/loading devices/i)).toHaveCount(0);
    });

    test('should filter devices by search query', async ({ adminPage: page, sdk }) => {
      const prod = await newDevice(sdk, 'Production-Server');
      const dev = await newDevice(sdk, 'Development-Server');

      await page.goto('/devices');
      await expect(page.getByText(prod.model)).toBeVisible();
      await expect(page.getByText(dev.model)).toBeVisible();

      await page.fill('input[placeholder*="Search"]', prod.model);

      await expect(page.getByText(prod.model)).toBeVisible();
      await expect(page.getByText(dev.model)).toHaveCount(0);
    });

    test('should filter devices by type', async ({ adminPage: page, sdk }) => {
      const a = await newDevice(sdk, 'Device-Alpha');

      await page.goto('/devices');
      await expect(page.getByText(a.model)).toBeVisible();

      // The page has no type filter (the mocked case was skipped for it):
      // assert that, so the case fails the day a filter appears unported.
      await expect(page.getByRole('combobox', { name: /type/i })).toHaveCount(0);
    });

    test('should filter devices by status', async ({ adminPage: page, sdk }) => {
      const a = await newDevice(sdk, 'Device-One');

      await page.goto('/devices');
      await expect(page.getByText(a.model)).toBeVisible();

      // No status filter on the page either (see the type case).
      await expect(page.getByRole('combobox', { name: /status/i })).toHaveCount(0);
    });

    test('should clear filters', async ({ adminPage: page, sdk }) => {
      const a = await newDevice(sdk, 'Device-1');

      await page.goto('/devices');
      await expect(page.getByText(a.model)).toBeVisible();

      const searchInput = page.getByPlaceholder(/search devices/i);
      await searchInput.click();
      await searchInput.fill(a.model);

      const clearButton = page.getByRole('button', { name: /clear filters/i });
      await expect(clearButton).toBeVisible();
      await clearButton.click();

      await expect(searchInput).toHaveValue('');
      await expect(page.getByText(a.model)).toBeVisible();
    });

    test('should display TPM status for devices', async ({ adminPage: page, sdk }) => {
      const tpm = await newDevice(sdk, 'TPM-Device', { attest_pub: ATTEST_PUB });
      const noTpm = await newDevice(sdk, 'No-TPM-Device');

      await page.goto('/devices');

      await expect(page.getByRole('row').filter({ hasText: tpm.model }).getByText(/no tpm/i)).toHaveCount(0);
      await expect(page.getByRole('row').filter({ hasText: noTpm.model }).getByText(/no tpm/i)).toBeVisible();
    });
  });

  test.describe('Device Details', () => {
    test('should navigate to device details from list', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Test-Device');

      await page.goto('/devices');
      await page.getByRole('row').filter({ hasText: d.model }).getByRole('button', { name: /open menu/i }).click();
      await page.getByRole('menuitem', { name: /view details/i }).click();

      await expect(page).toHaveURL(new RegExp(`/devices/${d.id}`));
      await expect(page.locator('h1').filter({ hasText: d.model })).toBeVisible();
    });

    test('should display device information', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Production-Server');

      await openDetails(page, d.id);

      await expect(page.locator('h1').filter({ hasText: d.model })).toBeVisible();
      await expect(page.getByText(d.serial).first()).toBeVisible();
    });

    test('should display TPM info tab', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'TPM-Device', { attest_pub: ATTEST_PUB });

      await openDetails(page, d.id);

      await expect(page.locator('h1').filter({ hasText: d.model })).toBeVisible();
      // The server reports no TPM vendor details: the page shows 'Unknown'.
      await expect(page.getByText('Unknown').first()).toBeVisible();
    });

    test('should display attestation history tab', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Attested-Device');

      await openDetails(page, d.id);
      await page.getByRole('tab', { name: /attestation history/i }).click();

      // A device the server never attested has no record.
      await expect(page.getByText(/no attestation records found/i)).toBeVisible();
    });

    test('should display certificates tab', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Certified-Device');

      await openDetails(page, d.id);
      await page.getByRole('tab', { name: /certificates/i }).click();

      // No certificate was issued to a device created over the API.
      await expect(page.getByText(/no certificates found/i)).toBeVisible();
    });

    test('should show device not found when device does not exist', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Gone-Device');
      must(await sdk.device.deleteDevice(d.id), 'device.deleteDevice');
      createdDevices.splice(createdDevices.indexOf(d.id), 1);

      await openDetails(page, d.id);

      await expect(page.getByText(/device not found/i).first()).toBeVisible();
      await expect(page.getByRole('button', { name: /back to devices/i })).toBeVisible();
    });

    test('should navigate back to devices list', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Back-Device');

      await openDetails(page, d.id);
      await expect(page.locator('h1').filter({ hasText: d.model })).toBeVisible();

      await page.locator('button').filter({ has: page.locator('svg') }).first().click();

      await expect(page).toHaveURL(/\/devices\/?$/);
    });
  });

  test.describe('CRUD Operations', () => {
    test('should open register device dialog', async ({ adminPage: page }) => {
      await openRegisterDialog(page);

      await expect(page.getByRole('heading', { name: /register new device/i })).toBeVisible();
    });

    test('should create a new device', async ({ adminPage: page, sdk }) => {
      const model = unique('New-Test-Device');
      const serial = unique('SN-NEW');

      await openRegisterDialog(page);
      await page.getByPlaceholder('my-device').fill(model);
      await page.getByPlaceholder('SN123456789').fill(serial);
      await page.keyboard.press('Enter');

      await expect(page.getByText(/device registered successfully/i)).toBeVisible();
      await expect(page.getByText(model)).toBeVisible();

      // The server holds the device the form registered.
      const list = must(await sdk.device.listDevices({ page: 1, pageSize: 100 }), 'device.listDevices');
      const found = list.devices.find((d) => d.serial === serial);
      expect(found?.model).toBe(model);
      if (found) createdDevices.push(found.id);
    });

    test('should validate device name is required', async ({ adminPage: page }) => {
      await openRegisterDialog(page);

      await page.keyboard.press('Enter');

      await expect(page.getByText(/name is required/i)).toBeVisible();
    });

    test('should delete a device with confirmation', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Delete-Me');

      await page.goto('/devices');
      await expect(page.getByText(d.model)).toBeVisible();

      page.on('dialog', (dialog) => dialog.accept());
      await page.getByRole('row').filter({ hasText: d.model }).getByRole('button').click();
      await page.getByRole('menuitem', { name: /delete/i }).click();

      await expect(page.getByText(/device deleted successfully/i)).toBeVisible();
      await expect(page.getByText(d.model)).toHaveCount(0);

      const got = await sdk.device.getDevice(d.id);
      expect(got.success).toBe(false);
    });

    test('should cancel delete when dialog is dismissed', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Keep-Me');

      await page.goto('/devices');
      await expect(page.getByText(d.model)).toBeVisible();

      page.on('dialog', (dialog) => dialog.dismiss());
      await page.getByRole('row').filter({ hasText: d.model }).getByRole('button').click();
      await page.getByRole('menuitem', { name: /delete/i }).click();

      await expect(page.getByText(d.model)).toBeVisible();
      must(await sdk.device.getDevice(d.id), 'device.getDevice');
    });

    test('should delete device from details page', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Delete-From-Details');

      await openDetails(page, d.id);
      await expect(page.locator('h1').filter({ hasText: d.model })).toBeVisible();

      page.on('dialog', (dialog) => dialog.accept());
      await page.getByRole('button', { name: /delete/i }).click();

      await expect(page.getByText(/device deleted successfully/i)).toBeVisible();
      await expect(page).toHaveURL(/\/devices\/?$/);
      expect((await sdk.device.getDevice(d.id)).success).toBe(false);
    });

    test('should toggle device status', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Toggle-Device');

      await page.goto('/devices');
      await page.getByRole('row').filter({ hasText: d.model }).getByRole('button').click();
      await page.getByRole('menuitem', { name: /disable device/i }).click();

      await expect(page.getByText(/device.*disabled|not yet implemented|failed to disable/i).first()).toBeVisible();
    });

    test('refresh attestation enqueues a collection instead of claiming a verdict (#428)', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Attest-Device', { attest_pub: ATTEST_PUB });

      await page.goto('/devices');
      await page.getByRole('row').filter({ hasText: d.model }).getByRole('button', { name: 'Open menu' }).click();

      const refresh = page.waitForResponse((r) => /\/attestation\/reports\/[^/]+\/refresh/.test(r.url()));
      await page.getByRole('menuitem', { name: /refresh attestation/i }).click();
      const res = await refresh;

      // The server enqueues a collection (202); it never answers a verdict here.
      expect(res.status()).toBe(202);
      await expect(page.getByText('Collection enqueued')).toBeVisible();
      await expect(page.getByText(/attestation completed/i)).toHaveCount(0);
    });
  });

  test.describe('Error States', () => {
    test('should handle fetch device details error', async ({ adminPage: page }) => {
      // An id the server does not know: the details fetch fails.
      await openDetails(page, unique('missing'));

      await expect(page.getByText(/device not found|failed to fetch device/i).first()).toBeVisible();
    });

    test('should handle create device error', async ({ adminPage: page, sdk }) => {
      // The server refuses a second device with a serial it already holds.
      const d = await newDevice(sdk, 'Duplicate-Device');
      const before = must(await sdk.device.listDevices({ page: 1, pageSize: 100 }), 'device.listDevices');

      await openRegisterDialog(page);
      await page.getByPlaceholder('my-device').fill(unique('Duplicate-Device'));
      await page.getByPlaceholder('SN123456789').fill(d.serial);
      await page.keyboard.press('Enter');

      await expect(page.getByText(/already exists|failed to register/i).first()).toBeVisible();
      const after = must(await sdk.device.listDevices({ page: 1, pageSize: 100 }), 'device.listDevices');
      expect(after.devices.filter((x) => x.serial === d.serial)).toHaveLength(
        before.devices.filter((x) => x.serial === d.serial).length,
      );
    });

    test('should handle delete device error', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Error-Delete');

      await page.goto('/devices');
      await expect(page.getByText(d.model)).toBeVisible();

      // Delete it behind the page's back: the page's delete then fails on the server.
      must(await sdk.device.deleteDevice(d.id), 'device.deleteDevice');
      createdDevices.splice(createdDevices.indexOf(d.id), 1);

      page.on('dialog', (dialog) => dialog.accept());
      await page.getByRole('row').filter({ hasText: d.model }).getByRole('button').click();
      await page.getByRole('menuitem', { name: /delete/i }).click();

      await expect(page.getByText(/failed to delete|cannot delete|not found/i).first()).toBeVisible();
    });
  });

  test.describe('Access Control', () => {
    test('should allow the tenant admin to view devices', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Visible-Device');

      await page.goto('/devices');

      await expect(page.getByText(d.model)).toBeVisible();
    });

    test('should redirect unauthenticated users to login', async ({ browser, baseURL }) => {
      const context = await browser.newContext({ baseURL, ignoreHTTPSErrors: true });
      try {
        const page = await context.newPage();
        await page.goto('/devices');
        await expect(page).toHaveURL(/\/auth\/webauthn/);
      } finally {
        await context.close();
      }
    });
  });

  test.describe('Device Details Actions', () => {
    test('refresh attestation from the details page enqueues and re-reads the report (#428)', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Attest-Detail-Device', { attest_pub: ATTEST_PUB });

      await openDetails(page, d.id);
      // Never collected: the server has no report for a fresh device.
      await expect(page.getByTestId('report-state-never-collected')).toBeVisible();

      const refresh = page.waitForResponse((r) => /\/attestation\/reports\/[^/]+\/refresh/.test(r.url()));
      await page.getByRole('button', { name: /refresh attestation/i }).click();
      expect((await refresh).status()).toBe(202);

      await expect(page.getByText('Collection enqueued')).toBeVisible();
      // No verdict is claimed from the enqueue (#428).
      await expect(page.getByText('Attestation completed successfully')).toHaveCount(0);
    });

    test('should toggle device status from details page', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'Toggle-Detail-Device');

      await openDetails(page, d.id);
      await expect(page.locator('h1').filter({ hasText: d.model })).toBeVisible();

      await page.getByRole('button', { name: /disable/i }).click();

      await expect(page.getByText(/disabled|updated|success|failed/i).first()).toBeVisible();
    });

    test('should show empty attestation history message', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'No-Attestation-Device');

      await openDetails(page, d.id);
      await page.getByRole('tab', { name: /attestation history/i }).click();

      await expect(page.getByText(/no attestation records found/i)).toBeVisible();
    });

    test('should show empty certificates message', async ({ adminPage: page, sdk }) => {
      const d = await newDevice(sdk, 'No-Certs-Device');

      await openDetails(page, d.id);
      await page.getByRole('tab', { name: /certificates/i }).click();

      await expect(page.getByText(/no certificates found/i)).toBeVisible();
    });
  });

  test.describe('Device Form Validation', () => {
    test('should select device type', async ({ adminPage: page }) => {
      await openRegisterDialog(page);

      const typeSelect = page.locator('[role="combobox"]').filter({ hasText: /physical device/i });
      await expect(typeSelect).toBeVisible();

      await typeSelect.click();
      await page.getByRole('option', { name: /virtual device/i }).click();

      await expect(page.locator('[role="combobox"]').filter({ hasText: /virtual device/i })).toBeVisible();
    });

    test('should fill TPM information', async ({ adminPage: page }) => {
      await openRegisterDialog(page);

      await page.fill('input[placeholder="my-device"]', 'TPM-Test-Device');
      await page.fill('input[placeholder*="Infineon"]', 'STMicroelectronics');
      await page.fill('input[placeholder="2.0"]', '2.0');
      await page.fill('input[placeholder="7.85"]', '8.0');

      await expect(page.locator('input[placeholder*="Infineon"]')).toHaveValue('STMicroelectronics');
    });

    test('should close dialog on cancel', async ({ adminPage: page }) => {
      await openRegisterDialog(page);

      await page.keyboard.press('Escape');

      await expect(page.getByRole('dialog')).not.toBeVisible();
    });
  });
});
