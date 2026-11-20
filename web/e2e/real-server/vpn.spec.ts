/**
 * Real-server spec for the VPN page (row #2070, epic #1665).
 *
 * Covers every VPNService operation the page drives: GetStatus, ListPeers,
 * EnrolPeer, RevokePeer, ListPosturePolicies, GetPosturePolicy,
 * SetPosturePolicy and DeletePosturePolicy. State is seeded and read back
 * through the SDK against the harness server; nothing is route-mocked.
 */
import { test, expect } from './fixtures';

const VPN_PATH = '/networking/vpn';

// A module the server compiles as package vpn.posture.
const POLICY_MODULE = 'package vpn.posture\n\ndefault allow = true\n';

function unique(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

test.describe('VPN (real server)', () => {
  test('status view shows what GetStatus returns', async ({ adminPage, sdk }) => {
    const status = await sdk.vpn.getStatus();
    await adminPage.goto(VPN_PATH);
    await expect(adminPage.getByRole('heading', { name: 'VPN', exact: true })).toBeVisible();

    if (!status.success) {
      // The server answered with an error: either this node runs no VPN
      // control plane, or gateway telemetry is unavailable.
      await expect(
        adminPage.getByText(/no VPN control plane|Session status is unavailable/)
      ).toBeVisible();
      return;
    }
    const gateways = status.data?.gateways ?? [];
    if (gateways.length === 0) {
      await expect(adminPage.getByText('No gateway has reported yet.')).toBeVisible();
    } else {
      for (const gateway of gateways) {
        await expect(adminPage.getByRole('cell', { name: gateway.gatewayId }).first()).toBeVisible();
      }
    }
  });

  test('peers: list shows a seeded peer, revoke removes it on the server', async ({
    adminPage,
    sdk,
    tenant,
  }) => {
    const deviceId = unique('e2e-vpn-dev');
    const enrolled = await sdk.vpn.enrolPeer({ tenantId: tenant.id, deviceId, zones: ['management'] });
    expect(enrolled.success).toBe(true);

    await adminPage.goto(VPN_PATH);
    const row = adminPage.getByRole('row').filter({ hasText: deviceId });
    await expect(row).toBeVisible();
    await expect(row).toContainText('management');

    await adminPage.getByRole('button', { name: `Revoke ${deviceId}` }).click();
    await adminPage.getByRole('button', { name: 'Confirm Revoke' }).click();
    await expect(row).toHaveCount(0);

    const after = await sdk.vpn.listPeers(tenant.id);
    expect(after.success).toBe(true);
    expect((after.data?.peers ?? []).map((p: { deviceId: string }) => p.deviceId)).not.toContain(deviceId);
  });

  test('peers: enrol through the dialog stores the peer with its zones', async ({
    adminPage,
    sdk,
    tenant,
  }) => {
    const deviceId = unique('e2e-vpn-enrol');
    await adminPage.goto(VPN_PATH);

    await adminPage.getByRole('button', { name: 'Enrol Peer' }).click();
    await adminPage.getByLabel('Tenant *').fill(tenant.id);
    await adminPage.getByLabel('Device ID *').fill(deviceId);
    await adminPage.getByLabel('Zones').fill('management, storage');
    await adminPage.getByRole('button', { name: 'Enrol', exact: true }).click();

    await expect(adminPage.getByRole('row').filter({ hasText: deviceId })).toBeVisible();

    const listed = await sdk.vpn.listPeers(tenant.id);
    expect(listed.success).toBe(true);
    const peer = (listed.data?.peers ?? []).find((p: { deviceId: string }) => p.deviceId === deviceId);
    expect(peer?.zones).toEqual(['management', 'storage']);

    await sdk.vpn.revokePeer(tenant.id, deviceId);
  });

  test('posture policies: create, view, edit and delete', async ({ adminPage, sdk, tenant }) => {
    const name = unique('e2e-posture');
    await adminPage.goto(VPN_PATH);

    // SetPosturePolicy through the New Policy dialog.
    await adminPage.getByRole('button', { name: 'New Policy' }).click();
    await adminPage.getByLabel('Tenant *').fill(tenant.id);
    await adminPage.getByLabel('Name *').fill(name);
    await adminPage.getByLabel('Module *').fill(POLICY_MODULE);
    await adminPage.getByRole('button', { name: 'Save' }).click();

    const row = adminPage.getByRole('row').filter({ hasText: name });
    await expect(row).toBeVisible();
    const stored = await sdk.vpn.getPosturePolicy(tenant.id, name);
    expect(stored.success).toBe(true);
    expect(stored.data?.policy?.module).toContain('package vpn.posture');

    // GetPosturePolicy through View / Edit, then replace the module.
    await adminPage.getByRole('button', { name: `Edit ${name}` }).click();
    const moduleField = adminPage.getByLabel('Module *');
    await expect(moduleField).toHaveValue(stored.data?.policy?.module ?? '');
    const edited = `${POLICY_MODULE}\n# edited by e2e\n`;
    await moduleField.fill(edited);
    await adminPage.getByRole('button', { name: 'Save' }).click();
    await expect(adminPage.getByText(`Saved posture policy ${name}`)).toBeVisible();
    const replaced = await sdk.vpn.getPosturePolicy(tenant.id, name);
    expect(replaced.data?.policy?.module).toContain('# edited by e2e');

    // DeletePosturePolicy.
    await adminPage.getByRole('button', { name: `Delete ${name}` }).click();
    await adminPage.getByRole('button', { name: 'Confirm Delete' }).click();
    await expect(row).toHaveCount(0);
    const listed = await sdk.vpn.listPosturePolicies(tenant.id);
    expect((listed.data?.policies ?? []).map((p: { name: string }) => p.name)).not.toContain(name);
  });

  test('posture policies: a module that does not compile is refused and not stored', async ({
    adminPage,
    sdk,
    tenant,
  }) => {
    const name = unique('e2e-posture-bad');
    await adminPage.goto(VPN_PATH);

    await adminPage.getByRole('button', { name: 'New Policy' }).click();
    await adminPage.getByLabel('Tenant *').fill(tenant.id);
    await adminPage.getByLabel('Name *').fill(name);
    await adminPage.getByLabel('Module *').fill('package not.posture\n\nallow {{\n');
    await adminPage.getByRole('button', { name: 'Save' }).click();

    await expect(adminPage.getByText('Failed to save posture policy')).toBeVisible();
    // The dialog stays open so the operator can fix the module.
    await expect(adminPage.getByLabel('Module *')).toBeVisible();

    const got = await sdk.vpn.getPosturePolicy(tenant.id, name);
    expect(got.success).toBe(false);
  });
});
