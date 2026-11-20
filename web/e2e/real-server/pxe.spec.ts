/**
 * PXE operations against the real server (#2062, epic #1665, ruling 972).
 *
 * Every device is seeded through the SDK, never through a route mock, and
 * each flow asserts on what the server returns afterwards. When this server
 * does not serve PXE (a control plane answers 503: PXE lives on the gateway
 * role), the device flows are skipped with that reason and the page's
 * service-unavailable state is asserted instead.
 */
import type { Page } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

/** The harness fixtures this spec uses (web/e2e/real-server/fixtures). */
type Fixtures = { adminPage: Page; sdk: PlatformClient };

const PXE_PATH = '/networking/pxe';

/** A locally administered unicast MAC unique to this run. */
function randomMAC(): string {
  const bytes = [0x02];
  for (let i = 0; i < 5; i++) bytes.push(Math.floor(Math.random() * 256));
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join(':');
}

/** Strips the proto enum prefix protojson emits (PROVISIONING_STATE_FAILED). */
function shortState(state: string | undefined): string {
  return String(state ?? '').replace(/^PROVISIONING_STATE_/, '');
}

async function pxeServed(sdk: PlatformClient): Promise<boolean> {
  const res = await sdk.pxe.getStatus();
  return res.success;
}

async function openDevice(page: Page, mac: string) {
  await page.goto(PXE_PATH);
  await page.getByLabel('Device MAC address').fill(mac);
  await page.getByRole('button', { name: 'Look up' }).click();
  const detail = page.getByTestId('pxe-device-detail');
  await expect(detail).toContainText(mac);
  return detail;
}

test.describe('PXE operations (real server)', () => {
  test('the page renders the service status or the unavailable state the server reports', async ({ adminPage, sdk }: Fixtures) => {
    const served = await pxeServed(sdk);
    await adminPage.goto(PXE_PATH);
    await expect(adminPage.getByRole('heading', { name: 'PXE Boot' })).toBeVisible();
    if (served) {
      await expect(adminPage.getByText('PXE Service Status')).toBeVisible();
    } else {
      await expect(adminPage.getByText(/not configured on this node/)).toBeVisible();
    }
  });

  test('look up a seeded device by MAC, open it and read its events', async ({ adminPage, sdk }: Fixtures) => {
    test.skip(!(await pxeServed(sdk)), 'PXE is not served by this node (503)');
    const mac = randomMAC();
    const reg = await sdk.pxe.registerDevice({ macAddress: mac });
    expect(reg.success).toBe(true);
    const deviceId = reg.data!.device!.id;

    const detail = await openDevice(adminPage, mac);
    await expect(detail).toContainText(deviceId);

    const byId = await sdk.pxe.getDevice(deviceId);
    expect(byId.success).toBe(true);
    await expect(detail.getByTestId('pxe-device-state')).toHaveText(shortState(byId.data!.device.state));

    const events = await sdk.pxe.getEvents(deviceId);
    expect(events.success).toBe(true);
    const list = detail.getByTestId('pxe-device-events');
    await expect(list.getByRole('listitem')).toHaveCount(events.data!.events?.length ?? 0);

    await sdk.pxe.removeDevice(deviceId);
  });

  test('quarantine, retry, update state, mark enrolled and authorize a device', async ({ adminPage, sdk }: Fixtures) => {
    test.skip(!(await pxeServed(sdk)), 'PXE is not served by this node (503)');
    const mac = randomMAC();
    const reg = await sdk.pxe.registerDevice({ macAddress: mac });
    expect(reg.success).toBe(true);
    const deviceId = reg.data!.device!.id;
    const stateOf = async () => shortState((await sdk.pxe.getDevice(deviceId)).data?.device.state);

    const detail = await openDevice(adminPage, mac);

    await detail.getByLabel('Quarantine reason').fill('e2e quarantine');
    await detail.getByRole('button', { name: 'Quarantine' }).click();
    await expect.poll(stateOf).toBe('QUARANTINED');
    await expect(detail.getByTestId('pxe-device-state')).toHaveText('QUARANTINED');

    await detail.getByRole('button', { name: 'Retry' }).click();
    await expect.poll(stateOf).not.toBe('QUARANTINED');

    await detail.getByLabel('New state').selectOption('FAILED');
    await detail.getByLabel('State reason').fill('e2e state change');
    await detail.getByRole('button', { name: 'Set state' }).click();
    await expect.poll(stateOf).toBe('FAILED');

    await detail.getByLabel('Certificate serial').fill('0a1b2c3d');
    await detail.getByRole('button', { name: 'Mark enrolled' }).click();
    await expect
      .poll(async () => (await sdk.pxe.getDevice(deviceId)).data?.device.certificateSerial)
      .toBe('0a1b2c3d');

    await detail.getByLabel('Target VLAN').fill('200');
    await detail.getByRole('button', { name: 'Authorize' }).click();
    await expect.poll(stateOf).toBe('AUTHORIZED');

    await sdk.pxe.removeDevice(deviceId);
  });

  test('remove a device from its detail panel', async ({ adminPage, sdk }: Fixtures) => {
    test.skip(!(await pxeServed(sdk)), 'PXE is not served by this node (503)');
    const mac = randomMAC();
    const reg = await sdk.pxe.registerDevice({ macAddress: mac });
    expect(reg.success).toBe(true);
    const deviceId = reg.data!.device!.id;

    const detail = await openDevice(adminPage, mac);
    await detail.getByRole('button', { name: 'Remove device' }).click();
    await adminPage.getByRole('button', { name: 'Confirm remove' }).click();
    await expect(detail).toBeHidden();

    const after = await sdk.pxe.getDevice(deviceId);
    expect(after.success).toBe(false);
  });

  test('stop and start the PXE service', async ({ adminPage, sdk }: Fixtures) => {
    test.skip(!(await pxeServed(sdk)), 'PXE is not served by this node (503)');
    await adminPage.goto(PXE_PATH);
    const running = async () => (await sdk.pxe.getStatus()).data?.status.running;

    if (await running()) {
      await adminPage.getByRole('button', { name: 'Stop service' }).click();
      await expect.poll(running).toBe(false);
    }
    await adminPage.getByRole('button', { name: 'Start service' }).click();
    await expect.poll(running).toBe(true);
  });

  test('the install-complete webhook is gated off with its reason', async ({ adminPage, sdk }: Fixtures) => {
    test.skip(!(await pxeServed(sdk)), 'PXE is not served by this node (503)');
    await adminPage.goto(PXE_PATH);
    const control = adminPage.getByRole('button', { name: 'Send install-complete webhook' });
    await expect(control).toBeDisabled();
    await expect(adminPage.getByTestId('pxe-webhook-gate-reason')).toContainText('machine-facing');
  });
});
