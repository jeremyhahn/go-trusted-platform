/**
 * PXE pages against the real platformd (#2062, UI epic #1665).
 *
 * /networking/pxe and /networking/pxe/[id] read the server's capability
 * answer and assert what the page must show for it: the not-configured
 * state or the listed devices, the gated Start/Stop control, and the detail
 * page's gated reads and UpdateState control. No route mocks: every answer
 * comes from the harness server.
 */
import type { Locator, Page, Response } from '@playwright/test';
import type {
  ApiResponse,
  CapabilitiesResponse,
  Capability,
  PXEDeviceInfo,
} from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

const LIST_DEVICES_OP = 'GET /api/v1/pxe/devices';
const STATUS_OP = 'GET /api/v1/pxe/status';
const START_OP = 'POST /api/v1/pxe/start';
const STOP_OP = 'POST /api/v1/pxe/stop';
const GET_DEVICE_OP = 'GET /api/v1/pxe/devices/{id}';
const UPDATE_STATE_OP = 'PUT /api/v1/pxe/devices/{id}/state';
const BY_MAC_OP = 'GET /api/v1/pxe/devices/mac/{mac}';

// The row actions of the All Devices list: aria-label `<prefix> <id>`, each gated on its op.
const ROW_ACTIONS: ReadonlyArray<readonly [string, string]> = [
  ['Authorize', 'POST /api/v1/pxe/devices/{id}/authorize'],
  ['Quarantine', 'POST /api/v1/pxe/devices/{id}/quarantine'],
  ['Retry', 'POST /api/v1/pxe/devices/{id}/retry'],
  ['Remove', 'DELETE /api/v1/pxe/devices/{id}'],
  ['Mark enrolled', 'POST /api/v1/pxe/devices/{id}/enrolled'],
];

const NOT_CONFIGURED = 'PXE is not available on this node';

function sdkData<T>(res: ApiResponse<T>, what: string): T {
  expect(res.success, `${what}: ${JSON.stringify(res.error)}`).toBeTruthy();
  if (res.data === undefined || res.data === null) throw new Error(`${what}: no data`);
  return res.data;
}

function capabilityOf(caps: CapabilitiesResponse, op: string): Capability {
  return caps.capabilities.find((c) => c.op === op) ?? { op, kind: 'route', enabled: false };
}

function apiResponse(page: Page, method: string, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && path.test(new URL(r.url()).pathname),
  );
}

async function expectGatedOff(control: Locator, cap: Capability): Promise<void> {
  await expect(control).toBeDisabled();
  if (cap.reason) await expect(control).toHaveAttribute('title', cap.reason);
}

async function expectNotConfigured(page: Page): Promise<void> {
  await expect(page.getByText(NOT_CONFIGURED)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Start PXE service' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Stop PXE service' })).toHaveCount(0);
}

test.describe('PXE against the real platformd (#2062)', () => {
  test('shows the PXE devices or the not-configured state the server answers', async ({
    adminPage,
    sdk,
  }) => {
    const caps = sdkData(await sdk.capabilities.list(), 'capabilities');
    if (!capabilityOf(caps, LIST_DEVICES_OP).enabled) {
      await adminPage.goto('/networking/pxe');
      await expectNotConfigured(adminPage);
      return;
    }

    const listed = apiResponse(adminPage, 'GET', /\/api\/v1\/pxe\/devices$/);
    await adminPage.goto('/networking/pxe');
    const r = await listed;
    expect(r.ok(), `ListDevices answered ${r.status()}`).toBeTruthy();
    const devices = unwrapPayload<{ devices?: PXEDeviceInfo[] }>(await r.json()).devices ?? [];
    for (const d of devices) {
      const link = adminPage.getByTestId(`pxe-device-link-${d.id}`);
      await expect(link).toBeVisible();
      await expect(link).toContainText(d.macAddress);
    }
  });

  test('the status card offers Start or Stop as the server allows', async ({ adminPage, sdk }) => {
    const caps = sdkData(await sdk.capabilities.list(), 'capabilities');
    if (!capabilityOf(caps, LIST_DEVICES_OP).enabled || !capabilityOf(caps, STATUS_OP).enabled) {
      await adminPage.goto('/networking/pxe');
      await expectNotConfigured(adminPage);
      return;
    }

    const running = sdkData(await sdk.pxe.getStatus(), 'pxe status').status.running;
    const name = running ? 'Stop PXE service' : 'Start PXE service';
    const cap = capabilityOf(caps, running ? STOP_OP : START_OP);

    await adminPage.goto('/networking/pxe');
    const button = adminPage.getByRole('button', { name });
    // Never click it: a real start binds the boot service on the node.
    if (!cap.enabled) {
      await expectGatedOff(button, cap);
    } else {
      await expect(button).toBeEnabled();
    }
  });

  test('the device detail page reads or withholds the device', async ({ adminPage, sdk }) => {
    const caps = sdkData(await sdk.capabilities.list(), 'capabilities');
    const getCap = capabilityOf(caps, GET_DEVICE_OP);
    const updateCap = capabilityOf(caps, UPDATE_STATE_OP);

    await adminPage.goto('/networking/pxe/e2e-no-such-device');
    if (!getCap.enabled) {
      const card = adminPage.getByTestId('pxe-device-not-enabled');
      await expect(card).toBeVisible();
      if (getCap.reason) await expect(card).toContainText(getCap.reason);
    } else {
      await expect(adminPage.getByTestId('pxe-device')).toBeVisible();
    }

    if (!updateCap.enabled) {
      await expectGatedOff(adminPage.getByRole('button', { name: 'Set state' }), updateCap);
    }
  });

  test('Find by MAC follows the server capability for GET /api/v1/pxe/devices/mac/{mac}', async ({
    adminPage,
    sdk,
  }) => {
    const caps = sdkData(await sdk.capabilities.list(), 'capabilities');
    await adminPage.goto('/networking/pxe');
    if (!capabilityOf(caps, LIST_DEVICES_OP).enabled) {
      await expectNotConfigured(adminPage);
      await expect(adminPage.getByLabel('MAC address')).toHaveCount(0);
      return;
    }

    const cap = capabilityOf(caps, BY_MAC_OP);
    await expect(adminPage.getByLabel('MAC address')).toBeVisible();
    const find = adminPage.getByRole('button', { name: 'Find by MAC' });
    await expect(find).toHaveAttribute('data-capability-op', BY_MAC_OP);
    await expect(find).toHaveAttribute('data-capability-enabled', String(cap.enabled));
    if (!cap.enabled) {
      await expectGatedOff(find, cap);
      return;
    }

    // A read only: no device carries this example MAC on a fresh test server.
    await adminPage.getByLabel('MAC address').fill('02:00:00:00:00:01');
    await find.click();
    await expect(adminPage.getByText('PXE lookup failed').first()).toBeVisible();
    await expect(adminPage).toHaveURL(/\/networking\/pxe$/);
  });

  test('every listed device row action follows its server capability', async ({ adminPage, sdk }) => {
    const caps = sdkData(await sdk.capabilities.list(), 'capabilities');
    await adminPage.goto('/networking/pxe');
    if (!capabilityOf(caps, LIST_DEVICES_OP).enabled) {
      await expectNotConfigured(adminPage);
      return;
    }

    // No writes from this spec: the row actions are checked on what the server already lists.
    const devices = sdkData(await sdk.pxe.listDevices(), 'pxe devices').devices ?? [];
    if (devices.length === 0) {
      await expect(adminPage.getByText('No devices found').first()).toBeVisible();
      return;
    }

    const id = devices[0].id;
    await expect(adminPage.getByTestId(`pxe-device-link-${id}`)).toBeVisible();
    for (const [prefix, op] of ROW_ACTIONS) {
      const button = adminPage.getByRole('button', { name: `${prefix} ${id}`, exact: true });
      if (prefix === 'Mark enrolled' && (await button.count()) === 0) continue;
      await expect(button).toHaveAttribute('data-capability-op', op);
      await expect(button).toHaveAttribute(
        'data-capability-enabled',
        String(capabilityOf(caps, op).enabled),
      );
      // Never click a row action: each one writes the device record.
    }
  });
});
