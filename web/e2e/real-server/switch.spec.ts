/**
 * Switch port operations against the real-server harness (#2066, epic #1665).
 *
 * The harness server either has a physical switch service wired or it does
 * not. When it does not, every /v1/switches route answers the structured 503
 * (service not configured) and the page must show the unavailable state with
 * no port control offered. When it does, the flows below drive each control
 * and assert on what the server returns afterwards through the SDK.
 */
import type { Page } from '@playwright/test';
import { isServiceNotConfigured } from 'trusted-platform-sdk';
import type { PlatformClient } from 'trusted-platform-sdk';

import { test, expect } from './fixtures';

type Fixtures = { adminPage: Page; sdk: PlatformClient };

const SWITCH_NAME = process.env.E2E_SWITCH_NAME ?? 'core-1';

type Probe =
  | { configured: true; ports: Array<{ port: string; mode: string; access_vlan: number; enabled: boolean }> }
  | { configured: false; notConfigured: boolean };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function probe(sdk: any): Promise<Probe> {
  try {
    const res = await sdk.switches.listPorts(SWITCH_NAME);
    if (res && res.success === false) {
      return { configured: false, notConfigured: isServiceNotConfigured(res.error ?? res) };
    }
    const ports = Array.isArray(res?.data) ? res.data : [];
    return { configured: true, ports };
  } catch (err) {
    return { configured: false, notConfigured: isServiceNotConfigured(err) };
  }
}

test.describe('switch ports', () => {
  test('the switch page reflects what ListPorts returns', async ({ adminPage, sdk }: Fixtures) => {
    const state = await probe(sdk);
    await adminPage.goto(`/networking/switches/${encodeURIComponent(SWITCH_NAME)}`);
    await expect(adminPage.getByRole('heading', { name: `Switch ${SWITCH_NAME}` })).toBeVisible();

    if (!state.configured) {
      // The server's structured 503: the page gates every port control off.
      expect(state.notConfigured).toBe(true);
      await expect(adminPage.getByText('Switch is not available on this node')).toBeVisible();
      await expect(adminPage.getByRole('button', { name: 'Enable' })).toHaveCount(0);
      await expect(adminPage.getByRole('button', { name: 'Disable' })).toHaveCount(0);
      await expect(adminPage.getByRole('button', { name: 'Set VLAN' })).toHaveCount(0);
      return;
    }

    for (const p of state.ports) {
      await expect(adminPage.getByTestId(`port-row-${p.port}`)).toBeVisible();
    }
  });

  test('GetPortStatus: the status dialog shows the port the server reports', async ({ adminPage, sdk }: Fixtures) => {
    const state = await probe(sdk);
    test.skip(!state.configured || state.ports.length === 0, 'no switch service or no ports on the harness server');
    if (!state.configured) return;
    const port = state.ports[0];

    const res = await sdk.switches.getPortStatus(SWITCH_NAME, port.port);
    expect(res.data?.port).toBe(port.port);

    await adminPage.goto(`/networking/switches/${encodeURIComponent(SWITCH_NAME)}`);
    await adminPage.getByTestId(`port-row-${port.port}`).getByRole('button', { name: 'Status' }).click();
    const status = adminPage.getByTestId('port-status');
    await expect(status).toBeVisible();
    await expect(status).toContainText(String(res.data?.mode ?? port.mode));
  });

  test('DisablePort then EnablePort: the server reports each admin state', async ({ adminPage, sdk }: Fixtures) => {
    const state = await probe(sdk);
    test.skip(!state.configured || state.ports.length === 0, 'no switch service or no ports on the harness server');
    if (!state.configured) return;
    const port = state.ports[0];

    // Seed a known starting state through the SDK.
    await sdk.switches.enablePort(SWITCH_NAME, port.port);

    await adminPage.goto(`/networking/switches/${encodeURIComponent(SWITCH_NAME)}`);
    const row = adminPage.getByTestId(`port-row-${port.port}`);

    await row.getByRole('button', { name: 'Disable' }).click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    await expect(row.getByRole('button', { name: 'Enable' })).toBeVisible();
    const afterDisable = await sdk.switches.listPorts(SWITCH_NAME);
    expect(afterDisable.data?.find((p: { port: string }) => p.port === port.port)?.enabled).toBe(false);

    await row.getByRole('button', { name: 'Enable' }).click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    await expect(row.getByRole('button', { name: 'Disable' })).toBeVisible();
    const afterEnable = await sdk.switches.listPorts(SWITCH_NAME);
    expect(afterEnable.data?.find((p: { port: string }) => p.port === port.port)?.enabled).toBe(true);
  });

  test('SetPortVLAN: the access VLAN the server reports changes', async ({ adminPage, sdk }: Fixtures) => {
    const state = await probe(sdk);
    const access = state.configured ? state.ports.find((p) => p.mode === 'access') : undefined;
    test.skip(!access, 'no switch service or no access port on the harness server');
    if (!access) return;

    const original = access.access_vlan || 1;
    const target = original === 100 ? 101 : 100;

    await adminPage.goto(`/networking/switches/${encodeURIComponent(SWITCH_NAME)}`);
    const row = adminPage.getByTestId(`port-row-${access.port}`);
    await row.getByRole('button', { name: 'Set VLAN' }).click();
    await adminPage.getByLabel('VLAN ID').fill(String(target));
    await adminPage.getByRole('button', { name: 'Save' }).click();

    await expect(row).toContainText(String(target));
    const after = await sdk.switches.getPortStatus(SWITCH_NAME, access.port);
    expect(after.data?.access_vlan).toBe(target);

    // Restore the seeded VLAN.
    await sdk.switches.setPortVLAN(SWITCH_NAME, access.port, original);
  });
});
