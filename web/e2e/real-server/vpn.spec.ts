import type { Page } from '@playwright/test';
import { expect, test } from './fixtures';

/**
 * VPN page against the real-server harness (#2070, epic #1665, ruling 972).
 *
 * Covers the 8 VPNService operations the page drives through the SDK:
 * GetStatus, ListPeers, ListPosturePolicies (the page load), EnrolPeer and
 * RevokePeer, SetPosturePolicy, GetPosturePolicy and DeletePosturePolicy.
 * It runs on the real-server harness (`make web-e2e`): no route is mocked,
 * the page is adminPage, signed in as the harness admin through the real
 * WebAuthn ceremony, and peers and policies go into the admin's own tenant
 * (the tenant fixture). A server without a VPN control plane skips the
 * spec; a refused status read (401, 403 or any other error) fails it.
 */

async function openVPNPage(page: Page) {
  const status = page.waitForResponse(
    (r) => r.url().includes('/api/v1/vpn/status') && r.request().method() === 'GET'
  );
  await page.goto('/networking/vpn');
  const peers = page.locator('[data-testid="vpn-peers-card"]');
  const unavailable = page.locator('[data-testid="vpn-unavailable"]');
  await expect(peers.or(unavailable)).toBeVisible();
  if (await unavailable.isVisible()) {
    status.catch(() => undefined);
    test.skip(true, 'this server runs no VPN control plane');
  }
  return status;
}

test.describe('VPN', () => {
  test('the page lists gateways, sessions, peers and policies', async ({ adminPage: page, tenant }) => {
    const status = await openVPNPage(page);

    expect((await status).status()).toBe(200);
    await expect(page.getByTestId('vpn-status-error')).toHaveCount(0);
    const gateways = page.getByTestId('vpn-gateways-card');
    await expect(
      gateways.getByTestId('vpn-gateways-table').or(gateways.getByText('No gateway has reported yet.'))
    ).toBeVisible();
    await expect(page.getByTestId('vpn-sessions-card')).toBeVisible();
    await expect(page.getByTestId('vpn-peers-card')).toBeVisible();
    await expect(page.getByTestId('vpn-policies-card')).toBeVisible();
  });

  test('enrol a peer, then revoke it', async ({ adminPage: page, tenant }) => {
    const device = `e2e-vpn-${Date.now()}`;
    await openVPNPage(page);
    const peers = page.getByTestId('vpn-peers-card');

    await page.getByRole('button', { name: 'Enrol Peer' }).click();
    await page.getByLabel('Tenant *').fill(tenant.id);
    await page.getByLabel('Device ID *').fill(device);
    await page.getByLabel('Zones').fill('management');
    await page.getByRole('button', { name: 'Enrol', exact: true }).click();
    await expect(peers.getByText(device)).toBeVisible();

    await page.getByRole('button', { name: `Revoke ${device}` }).click();
    await page.getByRole('button', { name: 'Confirm Revoke' }).click();
    await expect(peers.getByText(device)).toHaveCount(0);
  });

  test('create a posture policy, open it, save it, delete it', async ({ adminPage: page, tenant }) => {
    const name = `e2e-vpn-${Date.now()}`;
    await openVPNPage(page);
    const policies = page.getByTestId('vpn-policies-card');

    await page.getByRole('button', { name: 'New Policy' }).click();
    await page.getByLabel('Tenant *').fill(tenant.id);
    await page.getByLabel('Name *').fill(name);
    await page.getByLabel('Module *').fill('package vpn.posture\n');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(policies.getByText(name)).toBeVisible();

    await page.getByRole('button', { name: `Edit ${name}` }).click();
    await expect(page.getByLabel('Module *')).toHaveValue(/package vpn\.posture/);
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByLabel('Module *')).toHaveCount(0);

    await page.getByRole('button', { name: `Delete ${name}` }).click();
    await page.getByRole('button', { name: 'Confirm Delete' }).click();
    await expect(policies.getByText(name)).toHaveCount(0);
  });

  test('the write controls are open on a server that runs the VPN control plane', async ({ adminPage: page }) => {
    await openVPNPage(page);

    await expect(page.getByRole('button', { name: 'Enrol Peer' })).toHaveAttribute('data-capability-enabled', 'true');
    await expect(page.getByRole('button', { name: 'New Policy' })).toHaveAttribute('data-capability-enabled', 'true');
  });

  test('filter the peers by tenant and the status by gateway', async ({ adminPage: page, tenant }) => {
    const device = `e2e-vpn-filter-${Date.now()}`;
    await openVPNPage(page);
    const peers = page.getByTestId('vpn-peers-card');
    const filters = page.getByTestId('vpn-filters');

    await page.getByRole('button', { name: 'Enrol Peer' }).click();
    await page.getByLabel('Tenant *').fill(tenant.id);
    await page.getByLabel('Device ID *').fill(device);
    await page.getByLabel('Zones').fill('management');
    await page.getByRole('button', { name: 'Enrol', exact: true }).click();
    await expect(peers.getByText(device)).toBeVisible();

    // #vpn-filter-tenant, not getByLabel('Tenant'): the enrol dialog's
    // 'Tenant *' would match it too.
    await page.locator('#vpn-filter-tenant').fill(tenant.id);
    const filteredPeers = page.waitForResponse(
      (r) => r.url().includes('/api/v1/vpn/peers?tenant_id=') && r.request().method() === 'GET'
    );
    await filters.getByRole('button', { name: 'Apply filters' }).click();
    expect((await filteredPeers).status()).toBe(200);
    await expect(peers.getByText(device)).toBeVisible();

    await page.locator('#vpn-filter-gateway').fill('e2e-no-such-gateway');
    const filteredStatus = page.waitForResponse(
      (r) => r.url().includes('/api/v1/vpn/status?gateway_id=e2e-no-such-gateway') && r.request().method() === 'GET'
    );
    await page.locator('#vpn-filter-gateway').press('Enter');
    expect((await filteredStatus).status()).toBe(200);
    await expect(page.getByTestId('vpn-gateways-card').getByText('No gateway has reported yet.')).toBeVisible();

    await filters.getByRole('button', { name: 'Clear filters' }).click();
    await expect(page.locator('#vpn-filter-tenant')).toHaveValue('');
    await expect(peers.getByText(device)).toBeVisible();

    await page.getByRole('button', { name: `Revoke ${device}` }).click();
    await page.getByRole('button', { name: 'Confirm Revoke' }).click();
    await expect(peers.getByText(device)).toHaveCount(0);
  });
});
