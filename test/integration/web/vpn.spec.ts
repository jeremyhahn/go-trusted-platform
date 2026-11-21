import type { Page } from '@playwright/test';
import { test, expect } from './fixtures/auth.fixture';

/**
 * VPN page against the real-server harness (#2070, epic #1665, ruling 972).
 *
 * Covers the 8 VPNService operations the page drives through the SDK:
 * GetStatus, ListPeers, ListPosturePolicies (the page load), EnrolPeer and
 * RevokePeer, SetPosturePolicy, GetPosturePolicy and DeletePosturePolicy.
 * No route is mocked: a server without a VPN control plane skips the spec.
 */

const TENANT = 'test-tenant-id';

async function openVPNPage(page: Page) {
  await page.goto('/networking/vpn');
  const peers = page.locator('[data-testid="vpn-peers-card"]');
  const unavailable = page.locator('[data-testid="vpn-unavailable"]');
  await expect(peers.or(unavailable)).toBeVisible();
  if (await unavailable.isVisible()) {
    test.skip(true, 'this server runs no VPN control plane');
  }
}

test.describe('VPN', () => {
  test('the page lists gateways, sessions, peers and policies', async ({ authenticatedPage: page }) => {
    await openVPNPage(page);

    await expect(page.getByTestId('vpn-gateways-card')).toBeVisible();
    await expect(page.getByTestId('vpn-sessions-card')).toBeVisible();
    await expect(page.getByTestId('vpn-peers-card')).toBeVisible();
    await expect(page.getByTestId('vpn-policies-card')).toBeVisible();
  });

  test('enrol a peer, then revoke it', async ({ authenticatedPage: page }) => {
    const device = `e2e-vpn-${Date.now()}`;
    await openVPNPage(page);
    const peers = page.getByTestId('vpn-peers-card');

    await page.getByRole('button', { name: 'Enrol Peer' }).click();
    await page.getByLabel('Tenant *').fill(TENANT);
    await page.getByLabel('Device ID *').fill(device);
    await page.getByLabel('Zones').fill('management');
    await page.getByRole('button', { name: 'Enrol', exact: true }).click();
    await expect(peers.getByText(device)).toBeVisible();

    await page.getByRole('button', { name: `Revoke ${device}` }).click();
    await page.getByRole('button', { name: 'Confirm Revoke' }).click();
    await expect(peers.getByText(device)).toHaveCount(0);
  });

  test('create a posture policy, open it, save it, delete it', async ({ authenticatedPage: page }) => {
    const name = `e2e-vpn-${Date.now()}`;
    await openVPNPage(page);
    const policies = page.getByTestId('vpn-policies-card');

    await page.getByRole('button', { name: 'New Policy' }).click();
    await page.getByLabel('Tenant *').fill(TENANT);
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
});
