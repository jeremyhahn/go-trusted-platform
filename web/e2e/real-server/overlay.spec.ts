/**
 * Overlay operations against the real-server harness (#2059, epic #1665).
 *
 * State is seeded through the SDK client (`sdk`), never through route
 * mocks, and every assertion reads what the server returned.
 * Page: (dashboard)/networking/overlays/vteps.
 */
import { test, expect } from './fixtures';

const PAGE = '/networking/overlays/vteps';

/** A VNI unlikely to collide with seeded or parallel-test state. */
function testVni(): number {
  return 900000 + Math.floor(Math.random() * 99999);
}

test.describe('overlay (real server)', () => {
  test('GetOverlayStatus: the status card shows what the server reports', async ({ adminPage, sdk }) => {
    const res = await sdk.overlay.getStatus();
    expect(res.success).toBe(true);
    const status = res.data!.status;

    await adminPage.goto(PAGE);
    const card = adminPage.getByTestId('overlay-status');
    await expect(card).toBeVisible();
    await expect(card.getByTestId('overlay-status-health')).toHaveText(
      status.healthy ? 'healthy' : 'unhealthy'
    );
    await expect(card.getByTestId('overlay-status-vtep-count')).toHaveText(String(status.vtepCount));
    if (status.nodeId) {
      await expect(card).toContainText(status.nodeId);
    }
  });

  test('ListVTEPs and GetVTEP: the table lists every VTEP and Details opens it', async ({ adminPage, sdk }) => {
    const res = await sdk.overlay.listVTEPs();
    expect(res.success).toBe(true);
    const vteps = res.data?.vteps ?? [];

    await adminPage.goto(PAGE);
    const table = adminPage.getByTestId('vteps-table');
    if (vteps.length === 0) {
      await expect(table).toContainText('No VTEPs found');
      return;
    }
    for (const v of vteps) {
      await expect(table).toContainText(v.nodeId);
    }

    const first = vteps[0];
    const detail = await sdk.overlay.getVTEP(first.nodeId);
    expect(detail.success).toBe(true);
    await adminPage.getByRole('button', { name: `Details ${first.nodeId}` }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText(`VTEP ${first.nodeId}`);
    await expect(dialog).toContainText(detail.data!.vtep.ip);
  });

  test('ListTunnels and GetTunnelStats: the table lists every tunnel and Stats opens it', async ({ adminPage, sdk }) => {
    const res = await sdk.overlay.listTunnels();
    expect(res.success).toBe(true);
    const tunnels = res.data?.tunnels ?? [];

    await adminPage.goto(PAGE);
    if (tunnels.length === 0) {
      await expect(adminPage.getByText('No tunnels found')).toBeVisible();
      return;
    }
    const t = tunnels[0];
    const stats = await sdk.overlay.getTunnelStats({ remoteVtep: t.remoteVtep, vni: t.vni });
    expect(stats.success).toBe(true);
    await adminPage.getByRole('button', { name: `Stats ${t.remoteVtep} ${t.vni}` }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText('Tunnel statistics');
    await expect(dialog).toContainText(`${t.remoteVtep} on VNI ${t.vni}`);
  });

  test('DeleteVNI: a seeded VNI is deleted from the page and the server no longer lists it', async ({ adminPage, sdk }) => {
    const vni = testVni();
    const created = await sdk.overlay.createVNI({ config: { vni, name: `e2e-${vni}` } });
    expect(created.success).toBe(true);

    await adminPage.goto(PAGE);
    await adminPage.getByRole('button', { name: `Delete VNI ${vni}` }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
    await expect(adminPage.getByText('VNI deleted')).toBeVisible();
    await expect(adminPage.getByRole('button', { name: `Delete VNI ${vni}` })).toHaveCount(0);

    const after = await sdk.overlay.listVNIs();
    expect(after.success).toBe(true);
    expect((after.data?.vnis ?? []).some((v) => v.config.vni === vni)).toBe(false);
  });

  test('ListRemoteMACs and ForgetMAC: the MAC table follows the server and forget reports its answer', async ({ adminPage, sdk }) => {
    const vni = testVni();
    const created = await sdk.overlay.createVNI({ config: { vni, name: `e2e-mac-${vni}` } });
    expect(created.success).toBe(true);

    const listed = await sdk.overlay.listRemoteMACs();
    expect(listed.success).toBe(true);
    const macs = listed.data?.macs ?? [];

    await adminPage.goto(PAGE);
    for (const m of macs) {
      await expect(adminPage.getByRole('button', { name: `Forget ${m.mac} on VNI ${m.vni}` })).toBeVisible();
    }

    // Forget a MAC the server has not learned on the seeded VNI: the page
    // shows whatever the server answered (success or its error message).
    const mac = '02:00:5e:10:20:30';
    await adminPage.getByLabel('MAC address').fill(mac);
    await adminPage.getByLabel('VNI', { exact: true }).fill(String(vni));
    await adminPage.getByRole('button', { name: 'Forget MAC' }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Forget' }).click();

    const direct = await sdk.overlay.forgetMAC({ mac, vni });
    if (direct.success) {
      await expect(adminPage.getByText('MAC forgotten')).toBeVisible();
    } else {
      await expect(adminPage.getByText('Forget MAC failed')).toBeVisible();
    }

    await sdk.overlay.deleteVNI(vni);
  });
});
