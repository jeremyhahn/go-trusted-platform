import type { Page, Request, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

/**
 * Real-server port of the mocked gateway-bgp.spec.ts (#2035): BGP peers,
 * announced prefixes and IPAM allocations on /networking/gateway/bgp.
 *
 * Prefixes and allocations are seeded through the SDK (announcePrefix,
 * allocateIP) with unique values and removed afterwards. BGP peers cannot be
 * seeded, and the harness daemon may run without a BGP speaker or IPAM: each
 * case then asserts the page's handling of the server's real refusal. The
 * gaps are listed in docs/plans/1665-port-1.md.
 */

const PAGE = '/networking/gateway/bgp';

interface SentCall {
  method: string;
  path: string;
  query: Record<string, string>;
  body: unknown;
}

function uid(): string {
  return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
}

/** A unique /32 in TEST-NET-3 (RFC 5737). */
function uniquePrefix(): string {
  return `203.0.113.${1 + Math.floor(Math.random() * 254)}/32`;
}

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

/** Records the page's gateway calls, with the path after /gateway. */
function watchCalls(page: Page): SentCall[] {
  const calls: SentCall[] = [];
  page.on('request', (req: Request) => {
    const url = new URL(req.url());
    const at = url.pathname.indexOf('/gateway/');
    if (at < 0 || !url.pathname.includes('/api/')) return;
    let body: unknown = null;
    try {
      body = req.postDataJSON();
    } catch {
      body = req.postData();
    }
    calls.push({
      method: req.method(),
      path: url.pathname.slice(at + '/gateway'.length),
      query: Object.fromEntries(url.searchParams.entries()),
      body,
    });
  });
  return calls;
}

function answer(page: Page, method: string, suffix: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && new URL(r.url()).pathname.endsWith(`/gateway${suffix}`),
  );
}

/** The first IPAM pool the server lists, or null when IPAM answers none. */
async function firstPool(sdk: PlatformClient): Promise<string | null> {
  const res = await sdk.gateway.listIPAMPools();
  const pool = res.success ? res.data?.pools?.[0] : undefined;
  return pool ? String(pool.id) : null;
}

/** Allocates an IP through the SDK; null when the server refuses. */
async function seedAllocation(sdk: PlatformClient, poolId: string, hostname: string): Promise<string | null> {
  const res = await sdk.gateway.allocateIP({ poolId, deviceId: `dev-${uid()}`, hostname });
  const ip = res.success ? res.data?.allocation?.ip : undefined;
  return ip ?? null;
}

test.describe('Gateway BGP and IPAM', () => {
  // Gap: BGP peers cannot be seeded; the case asserts the peers the server
  // lists, or its refusal.
  test('lists BGP peers', async ({ adminPage: page, sdk }) => {
    await page.goto(PAGE);
    const res = await sdk.gateway.listBGPPeers();
    const table = page.getByRole('table', { name: 'BGP peers' });
    if (!res.success) {
      await expect(page.getByText('Could not load BGP peers')).toBeVisible();
      return;
    }
    const peer = res.data?.peers?.[0];
    if (!peer) {
      await expect(table).toBeVisible();
      return;
    }
    const row = table.getByRole('row', { name: new RegExp(escape(peer.address)) });
    await expect(row).toBeVisible();
    await expect(row).toContainText(String(peer.asn));
    await expect(row).toContainText(peer.state);
  });

  test('announces a prefix', async ({ adminPage: page, sdk }) => {
    const prefix = uniquePrefix();
    try {
      const calls = watchCalls(page);
      await page.goto(PAGE);
      await page.getByLabel('Prefix', { exact: true }).fill(prefix);
      await page.getByLabel('Next hop').fill('10.0.0.1');
      const announced = answer(page, 'POST', '/bgp/prefixes');
      await page.getByRole('button', { name: 'Announce' }).click();
      const res = await announced;

      expect(calls).toContainEqual(
        expect.objectContaining({ method: 'POST', path: '/bgp/prefixes', body: { prefix, next_hop: '10.0.0.1' } }),
      );
      const table = page.getByRole('table', { name: 'Announced prefixes' });
      const row = table.getByRole('row', { name: new RegExp(escape(prefix)) });
      if (res.ok()) await expect(row).toBeVisible();
      else await expect(row).toHaveCount(0);
    } finally {
      await sdk.gateway.withdrawPrefix({ prefix });
    }
  });

  test('withdraws a prefix after confirming', async ({ adminPage: page, sdk }) => {
    const prefix = uniquePrefix();
    const seeded = await sdk.gateway.announcePrefix({ prefix, nextHop: '10.0.0.1' });
    try {
      const calls = watchCalls(page);
      await page.goto(PAGE);
      if (!seeded.success) {
        // Gap: no BGP speaker on the harness node to announce to.
        await expect(page.getByText('Could not load announced prefixes')).toBeVisible();
        return;
      }
      const table = page.getByRole('table', { name: 'Announced prefixes' });
      await table.getByRole('button', { name: `Withdraw ${prefix}` }).click();

      const dialog = page.getByRole('dialog');
      await expect(dialog).toContainText(`Withdraw ${prefix}`);
      // Cancelling sends nothing.
      await dialog.getByRole('button', { name: 'Cancel' }).click();
      await expect(dialog).toBeHidden();
      expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(0);

      await table.getByRole('button', { name: `Withdraw ${prefix}` }).click();
      const withdrawn = answer(page, 'DELETE', '/bgp/prefixes');
      await page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();
      expect((await withdrawn).ok()).toBe(true);
      await expect(table.getByRole('row', { name: new RegExp(escape(prefix)) })).toHaveCount(0);
      expect(calls).toContainEqual(
        expect.objectContaining({ method: 'DELETE', path: '/bgp/prefixes', query: { prefix } }),
      );
      const listed = await sdk.gateway.listAnnouncedPrefixes();
      expect((listed.data?.prefixes ?? []).some((p) => p.prefix === prefix)).toBe(false);
    } finally {
      await sdk.gateway.withdrawPrefix({ prefix });
    }
  });

  test('allocates an IP', async ({ adminPage: page, sdk }) => {
    const pool = (await firstPool(sdk)) ?? 'prod-v4';
    const device = `dev-${uid()}`;
    const hostname = `node-${uid()}`;
    let ip: string | null = null;
    try {
      const calls = watchCalls(page);
      await page.goto(PAGE);
      await page.getByLabel('Pool ID').fill(pool);
      await page.getByLabel('Device ID').fill(device);
      await page.getByLabel('Hostname').fill(hostname);
      const allocated = answer(page, 'POST', '/ipam/allocations');
      await page.getByRole('button', { name: 'Allocate' }).click();
      const res = await allocated;

      expect(calls).toContainEqual(
        expect.objectContaining({
          method: 'POST',
          path: '/ipam/allocations',
          body: { pool_id: pool, device_id: device, hostname },
        }),
      );
      const table = page.getByRole('table', { name: 'IP allocations' });
      if (res.ok()) {
        const body = (await res.json()) as { ip?: string; allocation?: { ip?: string } };
        ip = body.allocation?.ip ?? body.ip ?? null;
        expect(ip).toBeTruthy();
        const row = table.getByRole('row', { name: new RegExp(escape(String(ip))) });
        await expect(row).toBeVisible();
        await expect(row).toContainText(hostname);
        await expect(row).toContainText(device);
      } else {
        // Gap: no IPAM pool on the harness node.
        await expect(table.getByRole('row', { name: new RegExp(escape(hostname)) })).toHaveCount(0);
      }
    } finally {
      if (ip) await sdk.gateway.releaseIP({ ip });
    }
  });

  test('allocate needs a device id', async ({ adminPage: page }) => {
    const calls = watchCalls(page);
    await page.goto(PAGE);
    await page.getByLabel('Pool ID').fill('prod-v4');
    await page.getByLabel('Hostname').fill(`node-${uid()}`);
    await expect(page.getByRole('button', { name: 'Allocate' })).toBeDisabled();
    expect(calls.filter((c) => c.method === 'POST')).toHaveLength(0);
  });

  test('releases an IP after confirming', async ({ adminPage: page, sdk }) => {
    const pool = await firstPool(sdk);
    const ip = pool ? await seedAllocation(sdk, pool, `node-${uid()}`) : null;
    try {
      const calls = watchCalls(page);
      await page.goto(PAGE);
      if (!ip) {
        // Gap: no IPAM pool on the harness node to allocate from.
        test.info().annotations.push({ type: 'gap', description: 'no IPAM pool to seed an allocation' });
        await expect(page.getByRole('table', { name: 'IP allocations' }).or(page.getByText('Could not load IP allocations'))).toBeVisible();
        return;
      }
      const table = page.getByRole('table', { name: 'IP allocations' });
      await table.getByRole('button', { name: `Release ${ip}` }).click();
      const dialog = page.getByRole('dialog');
      await expect(dialog).toContainText(`Release ${ip}`);
      const released = answer(page, 'DELETE', '/ipam/allocations');
      await dialog.getByRole('button', { name: 'Confirm' }).click();
      expect((await released).ok()).toBe(true);

      await expect(table.getByRole('button', { name: `Release ${ip}` })).toHaveCount(0);
      expect(calls).toContainEqual(expect.objectContaining({ method: 'DELETE', path: '/ipam/allocations', query: { ip } }));
    } finally {
      if (ip) await sdk.gateway.releaseIP({ ip });
    }
  });

  test('lists IPAM allocations', async ({ adminPage: page, sdk }) => {
    const pool = await firstPool(sdk);
    const hosts = [`node-${uid()}`, `node-${uid()}`];
    const ips: string[] = [];
    try {
      if (pool) {
        for (const h of hosts) {
          const ip = await seedAllocation(sdk, pool, h);
          if (ip) ips.push(ip);
        }
      }
      await page.goto(PAGE);
      const listed = await sdk.gateway.listAllocations();
      if (!listed.success) {
        await expect(page.getByText('Could not load IP allocations')).toBeVisible();
        return;
      }
      const table = page.getByRole('table', { name: 'IP allocations' });
      await expect(table).toBeVisible();
      for (let i = 0; i < ips.length; i++) {
        await expect(table.getByRole('row', { name: new RegExp(`${escape(ips[i])}.*${escape(hosts[i])}`) })).toBeVisible();
      }
    } finally {
      for (const ip of ips) await sdk.gateway.releaseIP({ ip });
    }
  });

  // The page loads BGP and IPAM independently: a refusal of one leaves the
  // other usable. The case asserts the server's real answer for each.
  test('a node without a BGP speaker still lists and releases allocations', async ({ adminPage: page, sdk }) => {
    const peers = await sdk.gateway.listBGPPeers();
    const allocations = await sdk.gateway.listAllocations();
    await page.goto(PAGE);
    if (!peers.success) {
      await expect(page.getByText('Could not load BGP peers')).toBeVisible();
      await expect(page.getByText('Could not load announced prefixes')).toBeVisible();
    } else {
      await expect(page.getByText('Could not load BGP peers')).toHaveCount(0);
    }
    if (allocations.success) {
      await expect(page.getByText('Could not load IP allocations')).toHaveCount(0);
      await expect(page.getByRole('table', { name: 'IP allocations' })).toBeVisible();
    } else {
      await expect(page.getByText('Could not load IP allocations')).toBeVisible();
    }
  });

  test('a node without IPAM still lists BGP peers', async ({ adminPage: page, sdk }) => {
    const peers = await sdk.gateway.listBGPPeers();
    const allocations = await sdk.gateway.listAllocations();
    await page.goto(PAGE);
    if (!allocations.success) {
      await expect(page.getByText('Could not load IP allocations')).toBeVisible();
    } else {
      await expect(page.getByText('Could not load IP allocations')).toHaveCount(0);
    }
    if (peers.success) {
      await expect(page.getByText('Could not load BGP peers')).toHaveCount(0);
      await expect(page.getByRole('table', { name: 'BGP peers' })).toBeVisible();
    } else {
      await expect(page.getByText('Could not load BGP peers')).toBeVisible();
    }
  });
});
