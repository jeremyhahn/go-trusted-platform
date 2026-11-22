/**
 * Switch ports (#1724, slice 29 of #1665) against the real server.
 *
 * Ported from web/e2e/switch-ports.spec.ts (#2037). The mocked spec answered
 * ListPorts, GetPortStatus, EnablePort, DisablePort and SetPortVLAN for a
 * canned switch core-1 through mockSwitchApi. The harness daemon configures
 * no managed switch and the API has no route to add one, so these tests
 * cover what the real server answers: the switches index opens a switch by
 * name, and a switch the daemon does not manage is refused by every port
 * route and shown as an error on the detail page.
 *
 * Gaps (docs/plans/1665-port-3.md): the port table, status panel, enable,
 * disable and VLAN dialogs and their failure toasts need a managed switch
 * in the harness.
 */

import { test, expect } from './fixtures';
import { daemonApi } from './fixtures/daemon-api';

const UNMANAGED = `e2e-unmanaged-${Date.now().toString(36)}`;

test.describe('Switch ports (real server)', () => {
  test('the switches index opens a switch by name', async ({ adminPage }) => {
    await adminPage.goto('/networking/switches');
    await expect(adminPage.getByRole('heading', { name: 'Switches' })).toBeVisible();
    const open = adminPage.getByRole('button', { name: 'Open' });
    await expect(open).toBeDisabled();

    await adminPage.getByLabel('Switch name').fill(UNMANAGED);
    await open.click();
    await expect(adminPage).toHaveURL(new RegExp(`/networking/switches/${UNMANAGED}/?$`));
  });

  test('ListPorts: an unmanaged switch shows the server error and no ports', async ({
    adminPage,
  }) => {
    const res = await daemonApi(adminPage).listSwitchPorts(UNMANAGED);
    expect(res.success).toBe(false);

    await adminPage.goto(`/networking/switches/${UNMANAGED}`);
    await expect(adminPage.getByText('Error Loading Switch Ports')).toBeVisible();
    await expect(adminPage.locator('[data-testid^="port-row-"]')).toHaveCount(0);

    const retry = adminPage.waitForResponse(
      (r) => r.url().includes(`/switches/${UNMANAGED}/ports`) && r.request().method() === 'GET',
    );
    await adminPage.getByRole('button', { name: 'Retry' }).click();
    expect((await retry).ok()).toBe(false);
    await expect(adminPage.getByText('Error Loading Switch Ports')).toBeVisible();
  });

  test('GetPortStatus: the server refuses a port of an unmanaged switch', async ({ adminPage }) => {
    const api = daemonApi(adminPage);
    const res = await api.getSwitchPortStatus(UNMANAGED, 'Eth1/1');
    expect(res.success).toBe(false);
  });

  test('EnablePort and DisablePort: the server refuses an unmanaged switch', async ({ adminPage }) => {
    const api = daemonApi(adminPage);
    expect((await api.enableSwitchPort(UNMANAGED, 'Eth1/1')).success).toBe(false);
    expect((await api.disableSwitchPort(UNMANAGED, 'Eth1/1')).success).toBe(false);
  });

  test('SetPortVLAN: the server refuses an unmanaged switch', async ({ adminPage }) => {
    const api = daemonApi(adminPage);
    const res = await api.setSwitchPortVLAN(UNMANAGED, 'Eth1/1', 200);
    expect(res.success).toBe(false);
  });
});
