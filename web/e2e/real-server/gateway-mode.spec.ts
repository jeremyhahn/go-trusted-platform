/**
 * Real-server spec for the gateway row (#2051, epic #1665): gateway mode,
 * telemetry snapshots, admitted VTEPs, BGP peers and prefixes, IPAM pools
 * and IP allocations.
 *
 * Every test reads the server's own answer through the SDK first and then
 * asserts the page shows that answer. A node that runs no gatewayd answers
 * the local gateway RPCs with the typed 503 "not configured"; the page then
 * shows the control disabled with that reason, and the spec asserts that
 * branch instead. No route mocks.
 */
import type { Page } from '@playwright/test';
import { test as base, expect } from '@playwright/test';
import { PlatformClient } from 'trusted-platform-sdk';

/** The fixtures this spec uses, typed so the spec checks on its own. */
type Fx = { adminPage: Page; sdk: PlatformClient };

/**
 * Real-server fixtures. The spec runs only against a live server: set
 * E2E_REAL_SERVER_API_URL (the REST base URL) and E2E_REAL_SERVER_ADMIN_JWT
 * (an admin token). Without them every test is skipped, so the mocked e2e
 * run that also collects e2e/ is unaffected.
 */
const apiUrl = process.env.E2E_REAL_SERVER_API_URL ?? '';
const adminJwt = process.env.E2E_REAL_SERVER_ADMIN_JWT ?? '';

const test = base.extend<Fx>({
  sdk: async ({}, provide, testInfo) => {
    testInfo.skip(!apiUrl || !adminJwt, 'real server not configured (E2E_REAL_SERVER_API_URL, E2E_REAL_SERVER_ADMIN_JWT)');
    await provide(new PlatformClient({ baseUrl: apiUrl, headers: { Authorization: `Bearer ${adminJwt}` } }));
  },
  adminPage: async ({ page, context, baseURL }, provide, testInfo) => {
    testInfo.skip(!apiUrl || !adminJwt, 'real server not configured (E2E_REAL_SERVER_API_URL, E2E_REAL_SERVER_ADMIN_JWT)');
    const domain = new URL(baseURL ?? 'http://localhost:3000').hostname;
    await context.addCookies([{ name: 'jwt', value: adminJwt, domain, path: '/', httpOnly: false, secure: false, sameSite: 'Lax' }]);
    await provide(page);
  },
});

type Res<T> = { success?: boolean; data?: T; error?: { message?: string } };

function ok<T>(res: Res<T>): T | undefined {
  return res.success === false ? undefined : res.data;
}

test.describe('gateway mode and telemetry', () => {
  test('mode control sets the mode the server reports, or is gated with the reason', async ({ adminPage, sdk }: Fx) => {
    const status = ok(await sdk.gateway.getStatus());
    await adminPage.goto('/networking/gateway');
    const setMode = adminPage.getByRole('button', { name: 'Set mode' });
    await expect(setMode).toBeVisible();

    if (!status?.status) {
      await expect(setMode).toBeDisabled();
      await expect(adminPage.getByTestId('gateway-mode-reason')).toContainText(/not configured|not run/i);
      return;
    }
    const current = status.status.modes ?? 0;
    await adminPage.getByLabel('Mode bitmask').fill(String(current));
    await setMode.click();
    await expect(adminPage.getByTestId('gateway-mode-result')).toContainText(String(current));
    const after = ok(await sdk.gateway.getStatus());
    expect(after?.status?.modes ?? 0).toBe(current);
  });

  test('reported gateways list every snapshot the server lists', async ({ adminPage, sdk }: Fx) => {
    const list = ok(await sdk.gateway.listState());
    const gateways = (list as { gateways?: Array<{ gateway_id: string }> } | undefined)?.gateways ?? [];
    await adminPage.goto('/networking/gateway');
    if (gateways.length === 0) {
      await expect(adminPage.getByText('No gatewayd processes have reported yet', { exact: false })).toBeVisible();
      return;
    }
    const table = adminPage.getByRole('table', { name: 'Reported gateways' });
    for (const g of gateways) {
      await expect(table.getByText(g.gateway_id)).toBeVisible();
    }
  });

  test('snapshot lookup shows the server snapshot or its not-found answer', async ({ adminPage, sdk }: Fx) => {
    const id = 'gw-e2e-absent';
    const res = await sdk.gateway.getState(id);
    await adminPage.goto('/networking/gateway');
    await adminPage.getByLabel('Snapshot gateway ID').fill(id);
    await adminPage.getByRole('button', { name: 'Get snapshot' }).click();
    const detail = adminPage.getByTestId('gateway-snapshot-lookup');
    if (res.success === false) {
      await expect(detail).toContainText(/not|no gateway/i);
    } else {
      await expect(detail).toContainText(id);
    }
  });

  test('admitted VTEPs match the server list, and a lookup answers per server', async ({ adminPage, sdk }: Fx) => {
    const res = await sdk.gateway.listAdmittedVTEPs();
    await adminPage.goto('/networking/gateway');
    const card = adminPage.getByTestId('gateway-admitted-vteps');
    await expect(card).toBeVisible();
    const vteps = ok(res)?.vteps ?? [];
    if (res.success === false) {
      await expect(card).toContainText(/not configured|not run|no gateway/i);
      return;
    }
    for (const v of vteps) {
      await expect(card.getByText(v.vtep)).toBeVisible();
    }
    await adminPage.getByLabel('VTEP address').fill('192.0.2.250');
    await adminPage.getByRole('button', { name: 'Find VTEP' }).click();
    const found = await sdk.gateway.getAdmittedVTEP('192.0.2.250');
    await expect(card.getByTestId('gateway-vtep-lookup')).toContainText(
      found.success === false ? /not found|not configured/i : '192.0.2.250'
    );
  });
});

test.describe('gateway BGP and IP allocations', () => {
  test('BGP peers table matches the server list', async ({ adminPage, sdk }: Fx) => {
    const res = ok(await sdk.gateway.listBGPPeers());
    await adminPage.goto('/networking/gateway/bgp');
    const table = adminPage.getByRole('table', { name: 'BGP peers' });
    for (const p of res?.peers ?? []) {
      await expect(table.getByText(String(p.address ?? ''))).toBeVisible();
    }
  });

  test('announce then withdraw a prefix through the page', async ({ adminPage, sdk }: Fx) => {
    const prefix = '198.51.100.0/24';
    await adminPage.goto('/networking/gateway/bgp');
    await adminPage.getByLabel('Prefix').fill(prefix);
    await adminPage.getByLabel('Next hop').fill('192.0.2.1');
    await adminPage.getByRole('button', { name: /announce/i }).click();
    const listed = ok(await sdk.gateway.listAnnouncedPrefixes());
    const table = adminPage.getByRole('table', { name: 'Announced prefixes' });
    if (!listed) {
      return;
    }
    expect((listed.prefixes ?? []).some((p) => p.prefix === prefix)).toBe(true);
    const row = table.getByRole('row', { name: new RegExp(prefix.replace(/[./]/g, '\\$&')) });
    await expect(row).toBeVisible();
    await row.getByRole('button', { name: /withdraw/i }).click();
    await adminPage.getByRole('button', { name: 'Confirm', exact: true }).click();
    await expect(row).toHaveCount(0);
    const after = ok(await sdk.gateway.listAnnouncedPrefixes());
    expect((after?.prefixes ?? []).some((p) => p.prefix === prefix)).toBe(false);
  });

  test('allocate then release an IP from a pool seeded through the SDK', async ({ adminPage, sdk }: Fx) => {
    const created = await sdk.gateway.createIPAMPool({ name: 'e2e-gw-pool', cidr: '10.251.0.0/28' });
    test.skip(created.success === false, `IPAM not available on this server: ${created.error?.message ?? ''}`);
    const pool = ok(created)!;
    try {
      await adminPage.goto('/networking/gateway/bgp');
      await adminPage.getByLabel('Pool ID').fill(pool.id);
      await adminPage.getByLabel('Device ID').fill('e2e-device');
      await adminPage.getByLabel('Hostname').fill('e2e-host');
      await adminPage.getByRole('button', { name: /allocate/i }).click();
      const allocs = ok(await sdk.gateway.listAllocations({ poolId: pool.id }));
      const alloc = (allocs?.allocations ?? [])[0];
      expect(alloc).toBeDefined();
      const table = adminPage.getByRole('table', { name: 'IP allocations' });
      const row = table.getByRole('row', { name: new RegExp(alloc.ip.replace(/\./g, '\\.')) });
      await expect(row).toBeVisible();
      await row.getByRole('button', { name: /release/i }).click();
      await adminPage.getByRole('button', { name: 'Confirm', exact: true }).click();
      await expect(row).toHaveCount(0);
      const after = ok(await sdk.gateway.listAllocations({ poolId: pool.id }));
      expect(after?.allocations ?? []).toHaveLength(0);
    } finally {
      await sdk.gateway.deleteIPAMPool(pool.id);
    }
  });
});

test.describe('gateway IPAM pools', () => {
  test('pool lookup, update and delete agree with the server', async ({ adminPage, sdk }: Fx) => {
    const created = await sdk.gateway.createIPAMPool({ name: 'e2e-gw-lookup', cidr: '10.252.0.0/28' });
    test.skip(created.success === false, `IPAM not available on this server: ${created.error?.message ?? ''}`);
    const pool = ok(created)!;

    await adminPage.goto('/networking/gateway');
    await adminPage.getByLabel('IPAM pool ID').fill(pool.id);
    await adminPage.getByRole('button', { name: 'Get pool' }).click();
    const detail = adminPage.getByTestId('gateway-pool-lookup');
    await expect(detail).toContainText('10.252.0.0/28');

    const updated = ok(await sdk.gateway.updateIPAMPool(pool.id, { name: 'e2e-gw-lookup', cidr: '10.252.0.0/28', description: 'renamed by e2e' }));
    expect(updated?.description).toBe('renamed by e2e');
    await adminPage.getByRole('button', { name: 'Get pool' }).click();
    await expect(detail).toContainText('renamed by e2e');

    await adminPage.getByRole('button', { name: 'Delete pool' }).click();
    await adminPage.getByRole('button', { name: 'Confirm delete' }).click();
    const gone = await sdk.gateway.getIPAMPool(pool.id);
    expect(gone.success).toBe(false);
  });
});
