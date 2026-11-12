import { test } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';

/**
 * Overlay VTEPs, tunnels, VNI delete and MAC forget (#1722, slice 22 of #1665).
 */
test.describe('Overlay VTEPs and tunnels', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test.fixme('ListVTEPs: lists VTEPs on the VTEPs page', async () => {});
  test.fixme('GetVTEP: shows one VTEP when selected', async () => {});
  test.fixme('DeleteVNI: deletes a VNI after confirmation', async () => {});
  test.fixme('ListTunnels: lists tunnels', async () => {});
  test.fixme('GetTunnelStats: shows tunnel statistics', async () => {});
  test.fixme('ForgetMAC: forgets a MAC after confirmation', async () => {});
});
