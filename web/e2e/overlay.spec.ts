import { test, expect, Page } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockOverlayApi, mockTenantApi, OverlayApiCall } from './fixtures/api-mock';

/**
 * Overlay VTEPs, tunnels, VNI delete and MAC forget (#1722, slice 22 of #1665).
 */

const vteps = [
  { nodeId: 'node-a', ip: '10.0.0.1', healthy: true, lastSeen: '2026-11-12T00:00:00Z' },
  { nodeId: 'node-b', ip: '10.0.0.2', healthy: false, lastSeen: '2026-11-11T23:00:00Z' },
];
const vnis = [
  { id: 'vni-5001', config: { vni: 5001, name: 'tenant-blue' }, createdAt: '2026-11-01T00:00:00Z', macCount: 3 },
];
const tunnels = [
  { localVtep: 'node-a', remoteVtep: 'node-b', vni: 5001, state: 'up', bytesTx: 4096, bytesRx: 8192 },
];

async function openPage(
  page: Page,
  failures: Record<string, number> = {},
  macs: Array<{ mac: string; vni: number; remoteVtep: string; learnedAt: string }> = []
): Promise<OverlayApiCall[]> {
  await mockTenantApi(page);
  const calls = await mockOverlayApi(page, { vteps, vnis, tunnels, macs, failures });
  await page.goto('/networking/overlays/vteps');
  await expect(page.getByRole('heading', { name: 'Overlay VTEPs' })).toBeVisible();
  return calls;
}

test.describe('Overlay VTEPs and tunnels', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('ListVTEPs: lists VTEPs on the VTEPs page', async ({ page }) => {
    const calls = await openPage(page);
    const table = page.getByTestId('vteps-table');
    await expect(table.getByRole('cell', { name: 'node-a', exact: true })).toBeVisible();
    await expect(table.getByRole('cell', { name: '10.0.0.2' })).toBeVisible();
    expect(calls.some((c) => c.method === 'GET' && c.path === '/vteps')).toBe(true);
  });

  test('GetVTEP: shows one VTEP when selected', async ({ page }) => {
    const calls = await openPage(page);
    await page.getByRole('button', { name: 'Details node-b' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('VTEP node-b')).toBeVisible();
    await expect(dialog.getByText('unhealthy')).toBeVisible();
    expect(calls.some((c) => c.method === 'GET' && c.path === '/vteps/node-b')).toBe(true);
  });

  test('DeleteVNI: deletes a VNI after confirmation', async ({ page }) => {
    const calls = await openPage(page);
    await page.getByRole('button', { name: 'Delete VNI 5001' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Delete VNI 5001?', { exact: false })).toBeVisible();
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);
    await dialog.getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByText('No VNIs found')).toBeVisible();
    expect(calls.some((c) => c.method === 'DELETE' && c.path === '/vnis/5001')).toBe(true);
  });

  test('DeleteVNI: cancel leaves the VNI in place', async ({ page }) => {
    const calls = await openPage(page);
    await page.getByRole('button', { name: 'Delete VNI 5001' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('cell', { name: 'tenant-blue' })).toBeVisible();
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);
  });

  test('ListTunnels: lists tunnels', async ({ page }) => {
    const calls = await openPage(page);
    await expect(page.getByRole('button', { name: 'Stats node-b 5001' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'up', exact: true })).toBeVisible();
    expect(calls.some((c) => c.method === 'GET' && c.path === '/tunnels')).toBe(true);
  });

  test('GetTunnelStats: shows tunnel statistics', async ({ page }) => {
    const calls = await openPage(page);
    await page.getByRole('button', { name: 'Stats node-b 5001' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Tunnel statistics')).toBeVisible();
    await expect(dialog.getByText('8192')).toBeVisible();
    expect(
      calls.some(
        (c) =>
          c.method === 'GET' &&
          c.path === '/tunnels/stats' &&
          c.query.remote_vtep === 'node-b' &&
          c.query.vni === '5001'
      )
    ).toBe(true);
  });

  test('ForgetMAC: forgets a MAC after confirmation', async ({ page }) => {
    const calls = await openPage(page);
    await page.getByLabel('MAC address').fill('aa:bb:cc:dd:ee:ff');
    await page.getByLabel('VNI', { exact: true }).fill('5001');
    await page.getByRole('button', { name: 'Forget MAC' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Forget MAC aa:bb:cc:dd:ee:ff on VNI 5001?')).toBeVisible();
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);
    await dialog.getByRole('button', { name: 'Forget' }).click();
    await expect(dialog).toBeHidden();
    expect(
      calls.some(
        (c) =>
          c.method === 'DELETE' &&
          c.path === '/macs' &&
          c.query.mac === 'aa:bb:cc:dd:ee:ff' &&
          c.query.vni === '5001'
      )
    ).toBe(true);
  });

  test('DeleteVNI: a denied delete shows an error and keeps the VNI', async ({ page }) => {
    const calls = await openPage(page, { 'DELETE /vnis/5001': 403 });
    await page.getByRole('button', { name: 'Delete VNI 5001' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByText('Delete VNI failed').first()).toBeVisible();
    await expect(page.getByText('VNI deleted')).toHaveCount(0);
    await expect(page.getByRole('cell', { name: 'tenant-blue' })).toBeVisible();
    expect(calls.some((c) => c.method === 'DELETE' && c.path === '/vnis/5001')).toBe(true);
  });

  test('ForgetMAC: a denied forget shows an error and keeps the inputs', async ({ page }) => {
    const calls = await openPage(page, { 'DELETE /macs': 403 });
    await page.getByLabel('MAC address').fill('aa:bb:cc:dd:ee:ff');
    await page.getByLabel('VNI', { exact: true }).fill('5001');
    await page.getByRole('button', { name: 'Forget MAC' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Forget' }).click();
    await expect(page.getByText('Forget MAC failed').first()).toBeVisible();
    await expect(page.getByText('MAC forgotten')).toHaveCount(0);
    await expect(page.getByLabel('MAC address')).toHaveValue('aa:bb:cc:dd:ee:ff');
    await expect(page.getByLabel('VNI', { exact: true })).toHaveValue('5001');
    expect(calls.some((c) => c.method === 'DELETE' && c.path === '/macs')).toBe(true);
  });

  test('ListVTEPs: a denied list shows an error, not an empty inventory', async ({ page }) => {
    await openPage(page, { 'GET /vteps': 403 });
    await expect(page.getByTestId('vteps-list-error')).toBeVisible();
    await expect(page.getByText('No VTEPs found')).toHaveCount(0);
  });

  test('ListTunnels: a denied tunnel list keeps VTEPs and VNIs usable', async ({ page }) => {
    await openPage(page, { 'GET /tunnels': 403 });
    await expect(page.getByTestId('tunnels-list-error')).toBeVisible();
    await expect(page.getByTestId('vteps-list-error')).toHaveCount(0);
    await expect(page.getByTestId('vnis-list-error')).toHaveCount(0);
    await expect(page.getByRole('cell', { name: 'node-a', exact: true })).toBeVisible();
    const del = page.getByRole('button', { name: 'Delete VNI 5001' });
    await expect(del).toBeVisible();
    await expect(del).toBeEnabled();
  });

  const learned = [
    { mac: '02:00:00:00:00:01', vni: 5001, remoteVtep: 'node-b', learnedAt: '2026-11-12T00:00:00Z' },
  ];

  test('ListRemoteMACs: lists learned remote MACs', async ({ page }) => {
    await openPage(page, {}, learned);
    await expect(page.getByRole('cell', { name: '02:00:00:00:00:01', exact: true })).toBeVisible();
  });

  test('ListRemoteMACs: forgets a listed MAC after confirmation', async ({ page }) => {
    const calls = await openPage(page, {}, learned);
    await page.getByRole('button', { name: 'Forget 02:00:00:00:00:01 on VNI 5001' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Forget MAC 02:00:00:00:00:01 on VNI 5001?')).toBeVisible();
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);
    await dialog.getByRole('button', { name: 'Forget' }).click();
    await expect(dialog).toBeHidden();
    expect(
      calls.some(
        (c) =>
          c.method === 'DELETE' &&
          c.path === '/macs' &&
          c.query.mac === '02:00:00:00:00:01' &&
          c.query.vni === '5001'
      )
    ).toBe(true);
    await expect(page.getByRole('cell', { name: '02:00:00:00:00:01', exact: true })).toHaveCount(0);
  });

  test('ListRemoteMACs: a denied MAC list keeps the other tables usable', async ({ page }) => {
    await openPage(page, { 'GET /macs': 403 }, learned);
    await expect(page.getByTestId('macs-list-error')).toBeVisible();
    await expect(page.getByTestId('vteps-list-error')).toHaveCount(0);
    const del = page.getByRole('button', { name: 'Delete VNI 5001' });
    await expect(del).toBeVisible();
    await expect(del).toBeEnabled();
  });

  test('ForgetMAC: an exponential VNI is read whole', async ({ page }) => {
    const calls = await openPage(page);
    await page.getByLabel('MAC address').fill('aa:bb:cc:dd:ee:ff');
    await page.getByLabel('VNI', { exact: true }).fill('1e4');
    await page.getByRole('button', { name: 'Forget MAC' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Forget MAC aa:bb:cc:dd:ee:ff on VNI 10000?')).toBeVisible();
    await dialog.getByRole('button', { name: 'Forget' }).click();
    await expect(dialog).toBeHidden();
    expect(
      calls.some((c) => c.method === 'DELETE' && c.path === '/macs' && c.query.vni === '10000')
    ).toBe(true);
  });

  test('ForgetMAC: a fractional VNI is refused before any request', async ({ page }) => {
    const calls = await openPage(page);
    await page.getByLabel('MAC address').fill('aa:bb:cc:dd:ee:ff');
    await page.getByLabel('VNI', { exact: true }).fill('5001.9');
    await page.getByRole('button', { name: 'Forget MAC' }).click();
    await expect(
      page.getByText('Enter a MAC address and a whole VNI from 1 to 16777215').first()
    ).toBeVisible();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);
  });
});
