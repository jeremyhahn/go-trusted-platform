/**
 * Switch ports E2E tests (#1724, slice 29 of #1665).
 *
 * Covers ListPorts, GetPortStatus, EnablePort, DisablePort and SetPortVLAN
 * from the switch detail page, with mocked API responses.
 */

import { test, expect, type Page } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import {
  mockSwitchApi,
  mockTenantApi,
  type SwitchApiCall,
  type SwitchPortStatus,
} from './fixtures/api-mock';

const SWITCH = 'core-1';

function ports(): SwitchPortStatus[] {
  return [
    { port: 'Eth1/1', mode: 'access', access_vlan: 100, enabled: true, link_up: true, description: 'uplink' },
    { port: 'Eth1/2', mode: 'trunk', access_vlan: 1, trunk_vlans: [100, 200], native_vlan: 1, enabled: false, link_up: false },
  ];
}

async function openSwitch(page: Page, failActions: string[] = []): Promise<SwitchApiCall[]> {
  const calls = await mockSwitchApi(page, { switchName: SWITCH, ports: ports(), failActions });
  await mockTenantApi(page);
  await page.goto(`/networking/switches/${SWITCH}`);
  await expect(page.getByRole('heading', { name: `Switch ${SWITCH}` })).toBeVisible();
  return calls;
}

test.describe('Switch ports', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('ListPorts: lists the ports of a switch', async ({ page }) => {
    const calls = await openSwitch(page);

    const first = page.getByTestId('port-row-Eth1/1');
    await expect(first).toContainText('access');
    await expect(first).toContainText('100');
    await expect(first).toContainText('enabled');
    await expect(page.getByTestId('port-row-Eth1/2')).toContainText('disabled');
    expect(calls.some((c) => c.method === 'GET' && c.port === undefined)).toBe(true);
  });

  test('GetPortStatus: shows the status of one port', async ({ page }) => {
    const calls = await openSwitch(page);

    await page.getByTestId('port-row-Eth1/2').getByRole('button', { name: 'Status' }).click();

    const status = page.getByTestId('port-status');
    await expect(status).toBeVisible();
    await expect(status).toContainText('trunk');
    await expect(status).toContainText('100, 200');
    expect(calls).toContainEqual(expect.objectContaining({ method: 'GET', port: 'Eth1/2', action: undefined }));
  });

  test('EnablePort: enables a port after confirmation', async ({ page }) => {
    const calls = await openSwitch(page);
    const row = page.getByTestId('port-row-Eth1/2');

    await row.getByRole('button', { name: 'Enable' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Enable port Eth1/2?');
    expect(calls.some((c) => c.action === 'enable')).toBe(false);

    await dialog.getByRole('button', { name: 'Confirm' }).click();

    await expect(row).toContainText('enabled');
    expect(calls).toContainEqual(expect.objectContaining({ method: 'POST', port: 'Eth1/2', action: 'enable' }));
  });

  test('DisablePort: disables a port after confirmation', async ({ page }) => {
    const calls = await openSwitch(page);
    const row = page.getByTestId('port-row-Eth1/1');

    await row.getByRole('button', { name: 'Disable' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Disable port Eth1/1?');

    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    expect(calls.some((c) => c.action === 'disable')).toBe(false);

    await row.getByRole('button', { name: 'Disable' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();

    await expect(row).toContainText('disabled');
    expect(calls).toContainEqual(expect.objectContaining({ method: 'POST', port: 'Eth1/1', action: 'disable' }));
  });

  test('SetPortVLAN: sets the VLAN of a port', async ({ page }) => {
    const calls = await openSwitch(page);
    const row = page.getByTestId('port-row-Eth1/1');

    await row.getByRole('button', { name: 'Set VLAN' }).click();
    const dialog = page.getByRole('dialog');
    const input = dialog.getByLabel('VLAN ID');

    await input.fill('4095');
    await expect(dialog.getByRole('button', { name: 'Save' })).toBeDisabled();

    await input.fill('200');
    await dialog.getByRole('button', { name: 'Save' }).click();

    await expect(row).toContainText('200');
    expect(calls).toContainEqual(
      expect.objectContaining({ method: 'POST', port: 'Eth1/1', action: 'vlan', body: { vlan_id: 200 } })
    );
  });

  test('SetPortVLAN: a trunk port offers no VLAN form', async ({ page }) => {
    await openSwitch(page);

    await expect(page.getByTestId('port-row-Eth1/1').getByRole('button', { name: 'Set VLAN' })).toHaveCount(1);
    await expect(page.getByTestId('port-row-Eth1/2').getByRole('button', { name: 'Set VLAN' })).toHaveCount(0);
  });

  test('GetPortStatus: link state comes from the port list', async ({ page }) => {
    const calls = await openSwitch(page);

    // Eth1/1 is up in the list; the single-port reply always says link_up false.
    await page.getByTestId('port-row-Eth1/1').getByRole('button', { name: 'Status' }).click();

    const status = page.getByTestId('port-status');
    await expect(status).toBeVisible();
    const link = status.getByText('Link', { exact: true }).locator('xpath=following-sibling::dd[1]');
    await expect(link).toHaveText('up');
    await expect(link).not.toHaveText('down');
    expect(calls).toContainEqual(expect.objectContaining({ method: 'GET', port: 'Eth1/1', action: undefined }));
  });

  test('GetPortStatus: admin state comes from the port list', async ({ page }) => {
    const calls = await openSwitch(page);

    // Eth1/2 is disabled in the list; the single-port reply always says enabled true.
    await page.getByTestId('port-row-Eth1/2').getByRole('button', { name: 'Status' }).click();

    const status = page.getByTestId('port-status');
    await expect(status).toBeVisible();
    const admin = status.getByText('Admin', { exact: true }).locator('xpath=following-sibling::dd[1]');
    await expect(admin).toHaveText('disabled');
    expect(calls).toContainEqual(expect.objectContaining({ method: 'GET', port: 'Eth1/2', action: undefined }));
  });

  test('GetPortStatus: a failed response shows an error and no status', async ({ page }) => {
    const calls = await openSwitch(page, ['status']);

    await page.getByTestId('port-row-Eth1/2').getByRole('button', { name: 'Status' }).click();

    await expect(page.getByText('Error loading port status').first()).toBeVisible();
    await expect(page.getByTestId('port-status')).toHaveCount(0);
    expect(calls).toContainEqual(expect.objectContaining({ method: 'GET', port: 'Eth1/2', action: undefined }));
  });

  test('EnablePort: a failed response shows an error and the port stays disabled', async ({ page }) => {
    const calls = await openSwitch(page, ['enable']);
    const row = page.getByTestId('port-row-Eth1/2');

    await row.getByRole('button', { name: 'Enable' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();

    await expect(page.getByText('Failed to enable port').first()).toBeVisible();
    await expect(page.getByText('Port Eth1/2 enabled')).toHaveCount(0);
    await expect(row).toContainText('disabled');
    expect(calls).toContainEqual(expect.objectContaining({ method: 'POST', port: 'Eth1/2', action: 'enable' }));
  });

  test('DisablePort: a failed response shows an error and the port stays enabled', async ({ page }) => {
    const calls = await openSwitch(page, ['disable']);
    const row = page.getByTestId('port-row-Eth1/1');

    await row.getByRole('button', { name: 'Disable' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();

    await expect(page.getByText('Failed to disable port').first()).toBeVisible();
    await expect(page.getByText('Port Eth1/1 disabled')).toHaveCount(0);
    await expect(row).toContainText('enabled');
    expect(calls).toContainEqual(expect.objectContaining({ method: 'POST', port: 'Eth1/1', action: 'disable' }));
  });

  test('SetPortVLAN: a failed response shows an error and the VLAN is unchanged', async ({ page }) => {
    const calls = await openSwitch(page, ['vlan']);
    const row = page.getByTestId('port-row-Eth1/1');

    await row.getByRole('button', { name: 'Set VLAN' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('VLAN ID').fill('200');
    await dialog.getByRole('button', { name: 'Save' }).click();

    await expect(page.getByText('Failed to set VLAN').first()).toBeVisible();
    await expect(page.getByText('Port Eth1/1 set to VLAN 200')).toHaveCount(0);
    await expect(row).toContainText('100');
    await expect(row).not.toContainText('200');
    expect(calls).toContainEqual(
      expect.objectContaining({ method: 'POST', port: 'Eth1/1', action: 'vlan', body: { vlan_id: 200 } })
    );
  });
});
