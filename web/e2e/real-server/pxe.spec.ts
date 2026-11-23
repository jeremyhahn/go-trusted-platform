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
});
