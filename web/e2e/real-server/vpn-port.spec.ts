import { test, expect } from './fixtures';
import type { Page } from '@playwright/test';

/**
 * VPN peers and posture policies against the real server.
 *
 * Ported from web/e2e/vpn.spec.ts (#2037). Peers are seeded through
 * sdk.vpn.enrolPeer and policies through sdk.vpn.setPosturePolicy; every UI
 * change is checked by reading the server back through the SDK. The status
 * card's gateway rows, session counts, refusals and leases were canned by the
 * mock with no gateway behind the harness and are listed as gaps in the PR
 * body.
 */

const unique = (prefix: string): string =>
  `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function must<T>(res: { success: boolean; data?: T; error?: any }, what: string): T {
  if (!res.success || res.data === undefined) {
    throw new Error(`${what} failed: ${JSON.stringify(res.error)}`);
  }
  return res.data;
}

async function openVPNPage(page: Page): Promise<void> {
  await page.goto('/networking/vpn');
  await expect(page.getByRole('heading', { name: 'VPN', exact: true })).toBeVisible();
}

test.describe('VPN peers and posture policies (real server)', () => {
  test('lists peers enrolled through the SDK', async ({ adminPage, sdk, tenant }) => {
    const device = unique('laptop');
    must(await sdk.vpn.enrolPeer({ tenantId: tenant.id, deviceId: device, zones: [] }), 'enrolPeer');

    await openVPNPage(adminPage);

    await expect(adminPage.getByText('Enrolled Peers')).toBeVisible();
    await expect(adminPage.getByRole('button', { name: `Revoke ${device}` })).toBeVisible();
    const row = adminPage.getByRole('row').filter({ hasText: device });
    await expect(row.getByRole('cell', { name: 'all allowed' })).toBeVisible();
  });

  test('enrols a peer and the server stores it', async ({ adminPage, sdk, tenant }) => {
    const device = unique('desktop');
    await openVPNPage(adminPage);

    await adminPage.getByRole('button', { name: 'Enrol Peer' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: 'Enrol VPN Peer' })).toBeVisible();
    const submit = dialog.getByRole('button', { name: 'Enrol', exact: true });
    await expect(submit).toBeDisabled();

    await dialog.locator('#vpn-peer-tenant').fill(tenant.id);
    await dialog.locator('#vpn-peer-device').fill(device);
    await dialog.locator('#vpn-peer-zones').fill('management, storage');
    await submit.click();

    await expect(dialog).toBeHidden();
    await expect(adminPage.getByRole('button', { name: `Revoke ${device}` })).toBeVisible();

    const peers = must(await sdk.vpn.listPeers(tenant.id), 'listPeers').peers as {
      deviceId: string;
      zones: string[];
    }[];
    const stored = peers.find((p) => p.deviceId === device);
    expect(stored?.zones).toEqual(['management', 'storage']);
  });

  test('revokes a peer behind its confirm', async ({ adminPage, sdk, tenant }) => {
    const keep = unique('keep');
    const revoke = unique('phone');
    must(await sdk.vpn.enrolPeer({ tenantId: tenant.id, deviceId: keep, zones: [] }), 'enrolPeer');
    must(await sdk.vpn.enrolPeer({ tenantId: tenant.id, deviceId: revoke, zones: [] }), 'enrolPeer');
    const listed = async (): Promise<string[]> =>
      (must(await sdk.vpn.listPeers(tenant.id), 'listPeers').peers as { deviceId: string }[]).map(
        (p) => p.deviceId,
      );

    await openVPNPage(adminPage);

    await adminPage.getByRole('button', { name: `Revoke ${revoke}` }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByText(`Revoke ${revoke} of tenant ${tenant.id}?`)).toBeVisible();
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    expect(await listed()).toContain(revoke);

    await adminPage.getByRole('button', { name: `Revoke ${revoke}` }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Confirm Revoke' }).click();

    await expect(adminPage.getByRole('button', { name: `Revoke ${revoke}` })).toBeHidden();
    await expect(adminPage.getByRole('button', { name: `Revoke ${keep}` })).toBeVisible();
    await expect.poll(listed).not.toContain(revoke);
  });

  test('status card reflects what the server reports', async ({ adminPage, sdk }) => {
    const status = await sdk.vpn.getStatus();
    expect(status.success).toBe(true);

    await openVPNPage(adminPage);

    await expect(adminPage.getByText(/status/i).first()).toBeVisible();
  });

  test('lists posture policies stored through the SDK', async ({ adminPage, sdk, tenant }) => {
    const name = unique('disk-encryption');
    must(
      await sdk.vpn.setPosturePolicy({
        tenantId: tenant.id,
        name,
        module: 'package vpn.posture\n\ndeny contains "disk" if not input.disk_encrypted\n',
      }),
      'setPosturePolicy',
    );

    await openVPNPage(adminPage);

    await expect(adminPage.getByText('Posture Policies')).toBeVisible();
    await expect(adminPage.getByRole('cell', { name })).toBeVisible();
  });

  test('opens a stored posture policy with its module', async ({ adminPage, sdk, tenant }) => {
    const name = unique('disk-encryption');
    const stored = 'package vpn.posture\n\ndeny contains "disk" if not input.disk_encrypted\n';
    must(await sdk.vpn.setPosturePolicy({ tenantId: tenant.id, name, module: stored }), 'setPosturePolicy');
    const server = must(await sdk.vpn.getPosturePolicy(tenant.id, name), 'getPosturePolicy');

    await openVPNPage(adminPage);
    await adminPage.getByRole('button', { name: `Edit ${name}` }).click();

    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: `Posture Policy ${name}` })).toBeVisible();
    await expect(dialog.locator('#vpn-policy-module')).toHaveValue(server.policy.module);
    await expect(dialog.locator('#vpn-policy-tenant')).toBeDisabled();
    await expect(dialog.locator('#vpn-policy-name')).toBeDisabled();
  });

  test('creates and edits a posture policy on the server', async ({ adminPage, sdk, tenant }) => {
    const name = unique('os-version');
    const regoModule = 'package vpn.posture\n\ndeny contains "os" if input.os_version < 14\n';
    const edited = 'package vpn.posture\n\ndefault allow := true\n';

    await openVPNPage(adminPage);
    await adminPage.getByRole('button', { name: 'New Policy' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: 'New Posture Policy' })).toBeVisible();
    await dialog.locator('#vpn-policy-tenant').fill(tenant.id);
    await dialog.locator('#vpn-policy-name').fill(name);
    await dialog.locator('#vpn-policy-module').fill(regoModule);
    await dialog.getByRole('button', { name: 'Save' }).click();

    await expect(dialog).toBeHidden();
    await expect(adminPage.getByRole('cell', { name })).toBeVisible();
    const created = must(await sdk.vpn.getPosturePolicy(tenant.id, name), 'getPosturePolicy');
    expect(created.policy.module).toBe(regoModule);

    await adminPage.getByRole('button', { name: `Edit ${name}` }).click();
    const editor = adminPage.getByRole('dialog');
    await editor.locator('#vpn-policy-module').fill(edited);
    await editor.getByRole('button', { name: 'Save' }).click();
    await expect(editor).toBeHidden();

    await expect
      .poll(async () => must(await sdk.vpn.getPosturePolicy(tenant.id, name), 'getPosturePolicy').policy.module)
      .toBe(edited);
  });

  test('a module that does not compile is refused', async ({ adminPage, sdk, tenant }) => {
    const name = unique('broken');

    await openVPNPage(adminPage);
    await adminPage.getByRole('button', { name: 'New Policy' }).click();
    const dialog = adminPage.getByRole('dialog');
    await dialog.locator('#vpn-policy-tenant').fill(tenant.id);
    await dialog.locator('#vpn-policy-name').fill(name);
    await dialog.locator('#vpn-policy-module').fill('package not.posture\n\nthis is not rego\n');
    await dialog.getByRole('button', { name: 'Save' }).click();

    await expect(dialog).toBeVisible();
    const list = must(await sdk.vpn.listPosturePolicies(tenant.id), 'listPosturePolicies');
    expect((list.policies as { name: string }[]).some((p) => p.name === name)).toBe(false);
  });

  test('deletes a posture policy behind its confirm', async ({ adminPage, sdk, tenant }) => {
    const name = unique('delete-me');
    must(
      await sdk.vpn.setPosturePolicy({
        tenantId: tenant.id,
        name,
        module: 'package vpn.posture\n\ndefault allow := true\n',
      }),
      'setPosturePolicy',
    );

    await openVPNPage(adminPage);
    await adminPage.getByRole('button', { name: `Delete ${name}` }).click();

    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByText(`Delete posture policy ${name} of tenant ${tenant.id}?`)).toBeVisible();
    await dialog.getByRole('button', { name: 'Confirm Delete' }).click();

    await expect(dialog).toBeHidden();
    await expect(adminPage.getByRole('cell', { name })).toBeHidden();
    const list = must(await sdk.vpn.listPosturePolicies(tenant.id), 'listPosturePolicies');
    expect((list.policies as { name: string }[]).some((p) => p.name === name)).toBe(false);
  });
});
