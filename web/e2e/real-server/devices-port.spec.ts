import type { Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The Devices Management cases of the mocked web/e2e/devices.spec.ts, against
 * the real-server harness (#2035, epic #1665).
 *
 * Every device is seeded through sdk.device under a unique serial and deleted
 * in afterEach; each case drives the page as the console does and asserts what
 * the server answered (the rendered row, badge, toast or navigation, or the
 * state the page shows for a refusal). A mocked case with no server behaviour
 * behind it is listed in its describe as a `// gap:` line; one another
 * real-server spec ports is listed as `// covered:`.
 */

/** A placeholder attest_pub: the page renders a TPM for it, the server cannot certify it. */
const PLACEHOLDER_ATTEST_PUB = 'e2e-not-a-key';

interface DeviceAnswer {
  id?: string | number;
  serial?: string;
  model?: string;
  state?: string;
  attest_cert?: string;
}

/**
 * The device the server answered: the SDK's res.data is the device itself,
 * not {device}; a raw Response.json() is the envelope, read through unwrapPayload.
 */
function deviceOf(data: unknown): DeviceAnswer {
  return (data ?? {}) as DeviceAnswer;
}

/** The message of a platform error envelope, in either of its two shapes. */
function serverMessage(body: unknown): string {
  const b = body as { error?: string | { message?: string } } | null;
  if (typeof b?.error === 'string') return b.error;
  return b?.error?.message ?? '';
}

function pathOf(r: Response): string {
  return new URL(r.url()).pathname;
}

function isList(r: Response): boolean {
  return r.request().method() === 'GET' && pathOf(r) === '/api/v1/devices';
}

function isGet(id: string): (r: Response) => boolean {
  return (r) => r.request().method() === 'GET' && pathOf(r) === `/api/v1/devices/${id}`;
}

function isCreate(r: Response): boolean {
  return r.request().method() === 'POST' && pathOf(r) === '/api/v1/devices';
}

function isDelete(id: string): (r: Response) => boolean {
  return (r) => r.request().method() === 'DELETE' && pathOf(r) === `/api/v1/devices/${id}`;
}

function isToggle(id: string, toggle: 'disable' | 'enable'): (r: Response) => boolean {
  return (r) => r.request().method() === 'POST' && pathOf(r) === `/api/v1/devices/${id}/${toggle}`;
}

/** Opens the device list and resolves once the server answered the listing. */
async function openDevices(page: Page): Promise<void> {
  const list = page.waitForResponse(isList);
  await page.goto('/devices/');
  expect((await list).ok()).toBe(true);
  await expect(page.getByText('Loading devices...')).toBeHidden();
}

/** The table row of the device with this serial (its Name button). */
function rowOf(page: Page, serial: string) {
  return page.getByRole('row').filter({ has: page.getByRole('button', { name: serial, exact: true }) });
}

/**
 * The device detail route is a static export: the build emits one page for
 * the `__placeholder__` id and the client resolves the real id from the URL.
 * Resolves with the server's answer to the device read.
 */
async function openDetail(page: Page, id: string): Promise<Response> {
  await page.goto('/devices/__placeholder__/');
  await page.getByText('Loading device details').waitFor();
  await page.waitForLoadState('networkidle');
  const answer = page.waitForResponse(isGet(id));
  await page.evaluate((deviceId) => window.history.pushState(null, '', `/devices/${deviceId}/`), id);
  return answer;
}

/** Opens the row menu of the device with this serial. */
async function openRowMenu(page: Page, serial: string): Promise<void> {
  await rowOf(page, serial).getByRole('button', { name: 'Open menu' }).click();
}

test.describe('Devices management, real server', () => {
  let seeded: string[] = [];
  let n = 0;

  /** Seeds a device through the SDK; the server answers with the device itself. */
  async function seed(sdk: PlatformClient, opts: { tpm?: boolean } = {}): Promise<{ id: string; serial: string }> {
    n += 1;
    const serial = `e2e-dev-${Date.now()}-${n}`;
    const res = await sdk.device.createDevice({
      device: opts.tpm ? { serial, model: serial, attest_pub: PLACEHOLDER_ATTEST_PUB } : { serial, model: serial },
    });
    expect(res.success, JSON.stringify(res.error)).toBe(true);
    const id = String(deviceOf(res.data).id ?? '');
    expect(id).not.toBe('');
    seeded.push(id);
    return { id, serial };
  }

  test.beforeEach(() => {
    seeded = [];
  });

  test.afterEach(async ({ sdk }) => {
    for (const id of seeded) {
      await sdk.device.deleteDevice(id).catch(() => undefined);
    }
  });

  test.describe('Device List', () => {
    test('should display device table with columns', async ({ adminPage, sdk }) => {
      const dev = await seed(sdk);
      await openDevices(adminPage);
      for (const column of ['Name', 'Type', 'TPM Status', 'Attestation', 'Last Seen', 'Status', 'Actions']) {
        await expect(adminPage.getByRole('columnheader', { name: column, exact: true })).toBeVisible();
      }
      await expect(rowOf(adminPage, dev.serial)).toBeVisible();
    });

    test('should display device status badges correctly', async ({ adminPage, sdk }) => {
      const fresh = await seed(sdk);
      const disabled = await seed(sdk);
      const dis = await sdk.device.disableDevice(disabled.id);
      expect(dis.success, JSON.stringify(dis.error)).toBe(true);
      const after = await sdk.device.getDevice(disabled.id);
      expect(deviceOf(after.data).state ?? '').toMatch(/disabl/i);

      await openDevices(adminPage);
      // No heartbeat was ever reported for either: the enforcement state wins
      // for the disabled one, the other was never seen.
      await expect(rowOf(adminPage, disabled.serial)).toContainText('Disabled');
      await expect(rowOf(adminPage, fresh.serial)).toContainText('Unknown');
      await expect(rowOf(adminPage, fresh.serial)).toContainText('Never');
    });

    test('should display device type badges correctly', async ({ adminPage, sdk }) => {
      // The server carries no physical/virtual type: the console renders every
      // device it lists as Physical.
      const dev = await seed(sdk);
      await openDevices(adminPage);
      await expect(rowOf(adminPage, dev.serial)).toContainText('Physical');
    });

    test('should show empty state when no devices', async ({ adminPage, sdk }) => {
      const missing = `e2e-dev-${Date.now()}-absent`;
      const listed = await sdk.device.listDevices({ page: 1, pageSize: 100 });
      expect(listed.success).toBe(true);
      const devices = ((listed.data as { devices?: DeviceAnswer[] } | undefined)?.devices ?? []);
      expect(devices.some((d) => d.serial === missing)).toBe(false);

      await openDevices(adminPage);
      await adminPage.getByPlaceholder('Search devices...').fill(missing);
      await expect(adminPage.getByText('No devices found')).toBeVisible();
    });

    // gap: should show loading state: the mock delayed the listing to catch the spinner; the real server answers before the spinner can be asserted reliably

    test('should filter devices by search query', async ({ adminPage, sdk }) => {
      const a = await seed(sdk);
      const b = await seed(sdk);
      await openDevices(adminPage);
      await expect(rowOf(adminPage, a.serial)).toBeVisible();
      await expect(rowOf(adminPage, b.serial)).toBeVisible();

      await adminPage.getByPlaceholder('Search devices...').fill(a.serial);
      await expect(rowOf(adminPage, a.serial)).toBeVisible();
      await expect(rowOf(adminPage, b.serial)).toBeHidden();
    });

    test('should clear filters', async ({ adminPage, sdk }) => {
      const a = await seed(sdk);
      const b = await seed(sdk);
      await openDevices(adminPage);
      const search = adminPage.getByPlaceholder('Search devices...');
      await search.fill(a.serial);
      await expect(rowOf(adminPage, b.serial)).toBeHidden();

      await adminPage.getByRole('button', { name: 'Clear filters' }).click();
      await expect(search).toHaveValue('');
      await expect(rowOf(adminPage, a.serial)).toBeVisible();
      await expect(rowOf(adminPage, b.serial)).toBeVisible();
      await expect(adminPage.getByRole('button', { name: 'Clear filters' })).toBeHidden();
    });

    test('should display TPM status for devices', async ({ adminPage, sdk }) => {
      const withTpm = await seed(sdk, { tpm: true });
      const without = await seed(sdk);
      await openDevices(adminPage);
      // The server holds an attestation key and no attestation certificate.
      await expect(rowOf(adminPage, withTpm.serial)).toContainText('No AK cert');
      await expect(rowOf(adminPage, without.serial)).toContainText('No TPM');
    });
  });

  test.describe('Device Details', () => {
    test('should navigate to device details from list', async ({ adminPage, sdk }) => {
      const dev = await seed(sdk);
      await openDevices(adminPage);
      await adminPage.getByRole('button', { name: dev.serial, exact: true }).click();
      await expect(adminPage).toHaveURL(new RegExp(`/devices/${dev.id}/?$`));
    });

    test('should display device information', async ({ adminPage, sdk }) => {
      const dev = await seed(sdk);
      const res = await openDetail(adminPage, dev.id);
      expect(res.ok()).toBe(true);
      expect(deviceOf(unwrapPayload(await res.json())).serial).toBe(dev.serial);
      await expect(adminPage.getByRole('heading', { name: dev.serial, exact: true })).toBeVisible();
      await expect(adminPage.getByText('Device details and management')).toBeVisible();
    });

    test('should display TPM info tab', async ({ adminPage, sdk }) => {
      const dev = await seed(sdk, { tpm: true });
      const res = await openDetail(adminPage, dev.id);
      expect(res.ok()).toBe(true);
      await expect(adminPage.getByRole('heading', { name: dev.serial, exact: true })).toBeVisible();
      // The server holds the attestation key and no certificate for it.
      expect(deviceOf(unwrapPayload(await res.json())).attest_cert ?? '').toBe('');
      await expect(adminPage.getByTestId('attest-cert-card')).toBeVisible();
      await expect(adminPage.getByTestId('attest-cert-absent')).toBeVisible();
    });

    test('should display attestation history tab', async ({ adminPage, sdk }) => {
      const dev = await seed(sdk);
      expect((await openDetail(adminPage, dev.id)).ok()).toBe(true);
      await expect(adminPage.getByRole('heading', { name: dev.serial, exact: true })).toBeVisible();
      await adminPage.getByRole('tab', { name: 'Attestation History' }).click();
      await expect(adminPage.getByText('Recent attestation records for this device')).toBeVisible();
      for (const column of ['Timestamp', 'Status', 'PCR Count', 'Details']) {
        await expect(adminPage.getByRole('columnheader', { name: column, exact: true })).toBeVisible();
      }
    });

    test('should display certificates tab', async ({ adminPage, sdk }) => {
      const dev = await seed(sdk);
      expect((await openDetail(adminPage, dev.id)).ok()).toBe(true);
      await expect(adminPage.getByRole('heading', { name: dev.serial, exact: true })).toBeVisible();
      await adminPage.getByRole('tab', { name: 'Certificates' }).click();
      await expect(adminPage.getByText('Device Certificates')).toBeVisible();
      for (const column of ['Type', 'Subject', 'Serial Number', 'Status', 'Expires']) {
        await expect(adminPage.getByRole('columnheader', { name: column, exact: true })).toBeVisible();
      }
    });

    test('should show device not found when device does not exist', async ({ adminPage, sdk }) => {
      const dev = await seed(sdk);
      expect((await sdk.device.deleteDevice(dev.id)).success).toBe(true);
      const res = await openDetail(adminPage, dev.id);
      expect(res.ok()).toBe(false);
      await expect(adminPage.getByText('Device not found')).toBeVisible();
    });

    test('should navigate back to devices list', async ({ adminPage, sdk }) => {
      const dev = await seed(sdk);
      expect((await sdk.device.deleteDevice(dev.id)).success).toBe(true);
      expect((await openDetail(adminPage, dev.id)).ok()).toBe(false);
      const list = adminPage.waitForResponse(isList);
      await adminPage.getByRole('button', { name: 'Back to Devices' }).click();
      await expect(adminPage).toHaveURL(/\/devices\/?$/);
      expect((await list).ok()).toBe(true);
      await expect(adminPage.getByRole('button', { name: 'Register Device' })).toBeVisible();
    });
  });

  test.describe('CRUD Operations', () => {
    test('should open register device dialog', async ({ adminPage }) => {
      await openDevices(adminPage);
      await adminPage.getByRole('button', { name: 'Register Device' }).click();
      const dialog = adminPage.getByRole('dialog');
      await expect(dialog.getByText('Register New Device')).toBeVisible();
      await expect(dialog.getByLabel('Serial Number')).toBeVisible();
    });

    test('should create a new device', async ({ adminPage, sdk }) => {
      const serial = `e2e-dev-${Date.now()}-created`;
      await openDevices(adminPage);
      await adminPage.getByRole('button', { name: 'Register Device' }).click();
      const dialog = adminPage.getByRole('dialog');
      await dialog.getByLabel('Serial Number').fill(serial);
      const answer = adminPage.waitForResponse(isCreate);
      await dialog.getByRole('button', { name: 'Register Device' }).click();
      const res = await answer;
      const body = await res.json().catch(() => null);
      expect(res.ok(), serverMessage(body)).toBe(true);
      const created = deviceOf(unwrapPayload(body));
      seeded.push(String(created.id ?? ''));
      expect(created.serial).toBe(serial);

      await expect(adminPage.getByText('Device registered successfully')).toBeVisible();
      await expect(dialog).toBeHidden();
      await expect(rowOf(adminPage, serial)).toBeVisible();
      const read = await sdk.device.getDevice(String(created.id));
      expect(deviceOf(read.data).serial).toBe(serial);
    });

    test('should validate device name is required', async ({ adminPage }) => {
      await openDevices(adminPage);
      let posted = false;
      adminPage.on('request', (r) => {
        if (r.method() === 'POST' && new URL(r.url()).pathname === '/api/v1/devices') posted = true;
      });
      await adminPage.getByRole('button', { name: 'Register Device' }).click();
      const dialog = adminPage.getByRole('dialog');
      await dialog.getByRole('button', { name: 'Register Device' }).click();
      await expect(dialog.getByText('Serial number is required')).toBeVisible();
      expect(posted).toBe(false);
    });

    test('should delete a device with confirmation', async ({ adminPage, sdk }) => {
      const dev = await seed(sdk);
      await openDevices(adminPage);
      adminPage.once('dialog', (d) => {
        expect(d.message()).toContain(dev.serial);
        void d.accept();
      });
      await openRowMenu(adminPage, dev.serial);
      const answer = adminPage.waitForResponse(isDelete(dev.id));
      await adminPage.getByRole('menuitem', { name: 'Delete' }).click();
      expect((await answer).ok()).toBe(true);
      await expect(adminPage.getByText('Device deleted successfully')).toBeVisible();
      await expect(rowOf(adminPage, dev.serial)).toBeHidden();
      expect((await sdk.device.getDevice(dev.id)).success).toBe(false);
    });

    test('should cancel delete when dialog is dismissed', async ({ adminPage, sdk }) => {
      const dev = await seed(sdk);
      await openDevices(adminPage);
      let deleted = false;
      adminPage.on('request', (r) => {
        if (r.method() === 'DELETE') deleted = true;
      });
      adminPage.once('dialog', (d) => void d.dismiss());
      await openRowMenu(adminPage, dev.serial);
      await adminPage.getByRole('menuitem', { name: 'Delete' }).click();
      await expect(rowOf(adminPage, dev.serial)).toBeVisible();
      expect(deleted).toBe(false);
      const read = await sdk.device.getDevice(dev.id);
      expect(deviceOf(read.data).serial).toBe(dev.serial);
    });

    test('should delete device from details page', async ({ adminPage, sdk }) => {
      const dev = await seed(sdk);
      expect((await openDetail(adminPage, dev.id)).ok()).toBe(true);
      await expect(adminPage.getByRole('heading', { name: dev.serial, exact: true })).toBeVisible();
      adminPage.once('dialog', (d) => void d.accept());
      const answer = adminPage.waitForResponse(isDelete(dev.id));
      await adminPage.getByRole('button', { name: 'Delete', exact: true }).click();
      expect((await answer).ok()).toBe(true);
      await expect(adminPage.getByText('Device deleted successfully')).toBeVisible();
      await expect(adminPage).toHaveURL(/\/devices\/?$/);
      expect((await sdk.device.getDevice(dev.id)).success).toBe(false);
    });

    test('should toggle device status', async ({ adminPage, sdk }) => {
      const dev = await seed(sdk);
      await openDevices(adminPage);
      adminPage.once('dialog', (d) => void d.accept());
      await openRowMenu(adminPage, dev.serial);
      const disabled = adminPage.waitForResponse(isToggle(dev.id, 'disable'));
      await adminPage.getByRole('menuitem', { name: 'Disable Device' }).click();
      expect((await disabled).ok()).toBe(true);
      await expect(rowOf(adminPage, dev.serial)).toContainText('Disabled');
      expect(deviceOf((await sdk.device.getDevice(dev.id)).data).state ?? '').toMatch(/disabl/i);

      await openRowMenu(adminPage, dev.serial);
      const enabled = adminPage.waitForResponse(isToggle(dev.id, 'enable'));
      await adminPage.getByRole('menuitem', { name: 'Enable Device' }).click();
      expect((await enabled).ok()).toBe(true);
      await expect(rowOf(adminPage, dev.serial)).not.toContainText('Disabled');
      expect(deviceOf((await sdk.device.getDevice(dev.id)).data).state ?? '').not.toMatch(/disabl/i);
    });

    // covered: refresh attestation enqueues a collection instead of claiming a verdict (#428): web/e2e/real-server/attestation-reports.spec.ts:175
  });

  test.describe('Error States', () => {
    // gap: should handle fetch devices error: the mock injected a 500 on the listing; the real server answers an authenticated admin's listing

    test('should handle fetch device details error', async ({ adminPage, sdk }) => {
      // A device deleted behind the page: the server refuses the read.
      const dev = await seed(sdk);
      expect((await sdk.device.deleteDevice(dev.id)).success).toBe(true);
      const res = await openDetail(adminPage, dev.id);
      expect(res.ok()).toBe(false);
      await expect(adminPage.getByText('Error', { exact: true })).toBeVisible();
      await expect(adminPage.getByText('Device not found')).toBeVisible();
    });

    test('should handle create device error', async ({ adminPage, sdk }) => {
      // The form registers a serial another device already holds.
      const dev = await seed(sdk);
      await openDevices(adminPage);
      await adminPage.getByRole('button', { name: 'Register Device' }).click();
      const dialog = adminPage.getByRole('dialog');
      await dialog.getByLabel('Serial Number').fill(dev.serial);
      const answer = adminPage.waitForResponse(isCreate);
      await dialog.getByRole('button', { name: 'Register Device' }).click();
      const res = await answer;
      const body = await res.json().catch(() => null);
      if (res.ok()) {
        // The server accepts a repeated serial: the page reports the device it registered.
        seeded.push(String(deviceOf(unwrapPayload(body)).id ?? ''));
        await expect(adminPage.getByText('Device registered successfully')).toBeVisible();
      } else {
        expect(serverMessage(body)).not.toBe('');
        await expect(adminPage.getByText('Error', { exact: true })).toBeVisible();
        await expect(dialog).toBeVisible();
      }
    });

    test('should handle delete device error', async ({ adminPage, sdk }) => {
      // The row is on screen, the device is deleted behind the page: the server refuses the delete.
      const dev = await seed(sdk);
      await openDevices(adminPage);
      await expect(rowOf(adminPage, dev.serial)).toBeVisible();
      expect((await sdk.device.deleteDevice(dev.id)).success).toBe(true);

      adminPage.once('dialog', (d) => void d.accept());
      await openRowMenu(adminPage, dev.serial);
      const answer = adminPage.waitForResponse(isDelete(dev.id));
      await adminPage.getByRole('menuitem', { name: 'Delete' }).click();
      const res = await answer;
      expect(res.ok()).toBe(false);
      await expect(adminPage.getByText('Error', { exact: true })).toBeVisible();
      await expect(adminPage.getByText('Device deleted successfully')).toBeHidden();
    });
  });

  test.describe('Access Control', () => {
    // gap: should allow tenant members to view devices: the harness signs in only its admin; it cannot create a tenant-member session

    test('should redirect unauthenticated users to login', async ({ page }) => {
      await page.goto('/devices/');
      await expect(page).toHaveURL(/\/(auth|login)/);
    });
  });

  test.describe('Device Details Actions', () => {
    // covered: refresh attestation from the details page enqueues and re-reads the report (#428): web/e2e/real-server/attestation-reports.spec.ts:137

    test('should toggle device status from details page', async ({ adminPage, sdk }) => {
      const dev = await seed(sdk);
      expect((await openDetail(adminPage, dev.id)).ok()).toBe(true);
      await expect(adminPage.getByRole('heading', { name: dev.serial, exact: true })).toBeVisible();

      adminPage.once('dialog', (d) => void d.accept());
      const disabled = adminPage.waitForResponse(isToggle(dev.id, 'disable'));
      await adminPage.getByRole('button', { name: 'Disable', exact: true }).click();
      expect((await disabled).ok()).toBe(true);
      await expect(adminPage.getByRole('button', { name: 'Enable', exact: true })).toBeVisible();
      expect(deviceOf((await sdk.device.getDevice(dev.id)).data).state ?? '').toMatch(/disabl/i);

      const enabled = adminPage.waitForResponse(isToggle(dev.id, 'enable'));
      await adminPage.getByRole('button', { name: 'Enable', exact: true }).click();
      expect((await enabled).ok()).toBe(true);
      await expect(adminPage.getByRole('button', { name: 'Disable', exact: true })).toBeVisible();
      expect(deviceOf((await sdk.device.getDevice(dev.id)).data).state ?? '').not.toMatch(/disabl/i);
    });

    test('should show empty attestation history message', async ({ adminPage, sdk }) => {
      // The page wires no attestation-history endpoint: a device the server holds shows none.
      const dev = await seed(sdk);
      expect((await openDetail(adminPage, dev.id)).ok()).toBe(true);
      await expect(adminPage.getByRole('heading', { name: dev.serial, exact: true })).toBeVisible();
      await adminPage.getByRole('tab', { name: 'Attestation History' }).click();
      await expect(adminPage.getByText('No attestation records found')).toBeVisible();
    });

    test('should show empty certificates message', async ({ adminPage, sdk }) => {
      // The page wires no per-device certificate endpoint: a device the server holds shows none.
      const dev = await seed(sdk);
      expect((await openDetail(adminPage, dev.id)).ok()).toBe(true);
      await expect(adminPage.getByRole('heading', { name: dev.serial, exact: true })).toBeVisible();
      await adminPage.getByRole('tab', { name: 'Certificates' }).click();
      await expect(adminPage.getByText('No certificates found')).toBeVisible();
    });
  });

  test.describe('Device Form Validation', () => {
    // gap: should select device type: the create contract stores the serial alone (#455); the server has no device type and the form no type field
    // gap: should fill TPM information: the create contract takes no operator-typed TPM details (#455); the form has no TPM fields

    test('should close dialog on cancel', async ({ adminPage }) => {
      await openDevices(adminPage);
      let posted = false;
      adminPage.on('request', (r) => {
        if (r.method() === 'POST' && new URL(r.url()).pathname === '/api/v1/devices') posted = true;
      });
      await adminPage.getByRole('button', { name: 'Register Device' }).click();
      const dialog = adminPage.getByRole('dialog');
      await dialog.getByLabel('Serial Number').fill(`e2e-dev-${Date.now()}-cancelled`);
      await dialog.getByRole('button', { name: 'Cancel' }).click();
      await expect(dialog).toBeHidden();
      expect(posted).toBe(false);
    });
  });
});
