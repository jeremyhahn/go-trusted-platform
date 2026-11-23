/**
 * Gateway BGP and IPAM page against the real-server harness (#2036, epic #1665).
 *
 * Ported from web/e2e/gateway-bgp.spec.ts (#2036, epic #1665, ruling 972).
 * Nothing is mocked: the BGP and IPAM states are read from the server first and
 * the page is held to whichever answer it gave; mocked cases with no server
 * behind them (canned peers, canned allocations, a node with a BGP speaker but
 * no IPAM or the reverse) are listed as gaps in the PR body. The harness
 * daemon runs no gatewayd today, so every read is expected to be refused; each
 * case still passes when a later config gives the node a BGP speaker or IPAM.
 * Test prefixes and next hops use 192.0.2.0/24.
 */
import type { Page, Response } from '@playwright/test';
import { test, expect } from './fixtures';

const PAGE = '/networking/gateway/bgp';
const PREFIXES_API = '/api/v1/gateway/bgp/prefixes';
const ALLOCATIONS_API = '/api/v1/gateway/ipam/allocations';

interface Result<T> {
  success: boolean;
  data?: T;
  error?: { message?: string } | unknown;
}

type Raw = Record<string, unknown>;

/** The part of the SDK these specs drive. */
interface GatewaySdk {
  gateway: {
    listBGPPeers(): Promise<Result<{ peers?: Raw[] }>>;
    announcePrefix(req: { prefix: string; nextHop?: string }): Promise<Result<unknown>>;
    withdrawPrefix(req: { prefix: string }): Promise<Result<unknown>>;
    listAnnouncedPrefixes(): Promise<Result<{ prefixes?: Raw[] }>>;
    listIPAMPools(): Promise<Result<{ pools?: Raw[] }>>;
    allocateIP(req: { poolId: string; deviceId?: string; hostname?: string }): Promise<Result<{ allocation?: Raw }>>;
    releaseIP(req: { ip: string }): Promise<Result<unknown>>;
    listAllocations(): Promise<Result<{ allocations?: Raw[] }>>;
  };
}

function gw(sdk: unknown): GatewaySdk['gateway'] {
  return (sdk as GatewaySdk).gateway;
}

function isNotConfigured(res: Result<unknown>): boolean {
  return JSON.stringify(res.error ?? {}).includes('SERVICE_NOT_CONFIGURED');
}

function errorMessage(res: Result<unknown>): string {
  const e = res.error as { message?: unknown } | undefined;
  return typeof e?.message === 'string' && e.message ? e.message : 'gateway request failed';
}

/** A field in lowerCamelCase or its proto (snake_case) name, as the page reads it. */
function field(r: Raw, camel: string, snake = camel): string {
  const v = r[camel] ?? r[snake];
  return v === undefined || v === null ? '' : String(v);
}

function rows(body: unknown, key: string): Raw[] {
  const v = body && typeof body === 'object' ? (body as Raw)[key] : undefined;
  return Array.isArray(v) ? v.filter((x): x is Raw => !!x && typeof x === 'object') : [];
}

function suffix(): string {
  return `${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
}

/** A /32 inside 192.0.2.0/24, unique enough per run. */
function testPrefix(): string {
  return `192.0.2.${2 + Math.floor(Math.random() * 250)}/32`;
}

/** Records which branch of the server's answer a case took. */
function branch(section: string, res: Result<unknown>): void {
  const state = res.success ? 'served' : isNotConfigured(res) ? 'not configured' : 'refused';
  test.info().annotations.push({ type: 'server', description: `${section}: ${state}` });
}

async function openPage(page: Page): Promise<void> {
  await page.goto(PAGE);
  await expect(page.getByRole('heading', { name: 'Gateway BGP & IPAM' })).toBeVisible();
  await expect(page.getByText('Loading…')).toHaveCount(0);
}

interface Section {
  table: string;
  errorTitle: string;
  empty: string;
  /** The text a row of this section is found by. */
  key: (r: Raw) => string;
  /** The row action's aria-label prefix, if the section has one. */
  action?: string;
}

const PEERS: Section = {
  table: 'BGP peers',
  errorTitle: 'Could not load BGP peers',
  empty: 'No BGP peers.',
  key: (r) => field(r, 'address'),
};

const PREFIXES: Section = {
  table: 'Announced prefixes',
  errorTitle: 'Could not load announced prefixes',
  empty: 'No announced prefixes.',
  key: (r) => field(r, 'prefix'),
  action: 'Withdraw',
};

const ALLOCATIONS: Section = {
  table: 'IP allocations',
  errorTitle: 'Could not load IP allocations',
  empty: 'No allocations.',
  key: (r) => field(r, 'ip'),
  action: 'Release',
};

/**
 * Holds one page section to the server's answer: its rows (or its empty-state
 * text) when the server served the list, its SectionError with the server's
 * message and no row action when the server refused it.
 */
async function expectSection(page: Page, s: Section, res: Result<unknown>, key: string): Promise<Raw[]> {
  const table = page.getByRole('table', { name: s.table });
  if (res.success) {
    const listed = rows(res.data, key);
    await expect(page.getByText(s.errorTitle)).toHaveCount(0);
    if (listed.length === 0) {
      await expect(table.getByText(s.empty)).toBeVisible();
    }
    for (const r of listed) {
      await expect(table.getByRole('row', { name: new RegExp(escapeRe(s.key(r))) }).first()).toBeVisible();
    }
    return listed;
  }
  const alert = page.getByRole('alert').filter({ hasText: s.errorTitle });
  await expect(alert).toBeVisible();
  await expect(alert).toContainText(errorMessage(res));
  await expect(table.getByText(s.empty)).toBeVisible();
  if (s.action) {
    await expect(table.getByRole('button', { name: new RegExp(`^${s.action} `) })).toHaveCount(0);
  }
  return [];
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function waitFor(page: Page, api: string, method: string): Promise<Response> {
  return page.waitForResponse((r) => r.url().includes(api) && r.request().method() === method);
}

/** True when the server accepted the request the page sent. */
async function accepted(res: Response): Promise<boolean> {
  if (!res.ok()) return false;
  const body: unknown = await res.json().catch(() => null);
  return !(body && typeof body === 'object' && (body as Raw).success === false);
}

/** A pool ID the server lists, or a made-up one the server must refuse. */
async function somePoolId(sdk: unknown): Promise<string> {
  const pools = await gw(sdk).listIPAMPools();
  branch('IPAM pools', pools);
  const first = rows(pools.data, 'pools')[0];
  const id = first ? field(first, 'id') || field(first, 'poolId', 'pool_id') || field(first, 'name') : '';
  return id || `e2e-pool-${suffix()}`;
}

test.describe('Gateway BGP and IPAM', () => {
  test('lists BGP peers', async ({ adminPage, sdk }) => {
    const peers = await gw(sdk).listBGPPeers();
    branch('BGP peers', peers);
    await openPage(adminPage);

    const listed = await expectSection(adminPage, PEERS, peers, 'peers');
    const table = adminPage.getByRole('table', { name: 'BGP peers' });
    for (const p of listed) {
      const row = table.getByRole('row', { name: new RegExp(escapeRe(field(p, 'address'))) }).first();
      await expect(row).toContainText(field(p, 'asn'));
      await expect(row).toContainText(field(p, 'state') || 'unknown');
    }
  });

  test('announces a prefix', async ({ adminPage, sdk }) => {
    const prefix = testPrefix();
    await openPage(adminPage);

    await adminPage.getByLabel('Prefix', { exact: true }).fill(prefix);
    await adminPage.getByLabel('Next hop').fill('192.0.2.1');
    const response = waitFor(adminPage, PREFIXES_API, 'POST');
    await adminPage.getByRole('button', { name: 'Announce' }).click();
    const ok = await accepted(await response);

    const table = adminPage.getByRole('table', { name: 'Announced prefixes' });
    const row = table.getByRole('row', { name: new RegExp(escapeRe(prefix)) });
    if (ok) {
      await expect(adminPage.getByText('Prefix announced').first()).toBeVisible();
      await expect(row).toBeVisible();
      const listed = await gw(sdk).listAnnouncedPrefixes();
      expect(listed.success, JSON.stringify(listed.error)).toBe(true);
      expect(rows(listed.data, 'prefixes').map((p) => field(p, 'prefix'))).toContain(prefix);
      await gw(sdk).withdrawPrefix({ prefix });
    } else {
      await expect(adminPage.getByText('Request failed').first()).toBeVisible();
      await expect(row).toHaveCount(0);
    }
  });

  test('withdraws a prefix after confirming', async ({ adminPage, sdk }) => {
    const prefix = testPrefix();
    const seeded = await gw(sdk).announcePrefix({ prefix, nextHop: '192.0.2.1' });
    branch('announce', seeded);
    const deletes: string[] = [];
    adminPage.on('request', (r) => {
      if (r.method() === 'DELETE' && r.url().includes(PREFIXES_API)) deletes.push(r.url());
    });
    await openPage(adminPage);

    const table = adminPage.getByRole('table', { name: 'Announced prefixes' });
    const withdraw = table.getByRole('button', { name: `Withdraw ${prefix}` });
    if (!seeded.success) {
      await expectSection(adminPage, PREFIXES, await gw(sdk).listAnnouncedPrefixes(), 'prefixes');
      await expect(withdraw).toHaveCount(0);
      return;
    }

    await withdraw.click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText(`Withdraw ${prefix}`);
    // Cancelling sends nothing and keeps the prefix on the server.
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    expect(deletes).toHaveLength(0);

    await withdraw.click();
    const response = waitFor(adminPage, PREFIXES_API, 'DELETE');
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();
    const ok = await accepted(await response);

    const listed = await gw(sdk).listAnnouncedPrefixes();
    const onServer = rows(listed.data, 'prefixes').map((p) => field(p, 'prefix'));
    if (ok) {
      await expect(adminPage.getByText('Prefix withdrawn').first()).toBeVisible();
      await expect(withdraw).toHaveCount(0);
      expect(onServer).not.toContain(prefix);
    } else {
      await expect(adminPage.getByText('Request failed').first()).toBeVisible();
      await gw(sdk).withdrawPrefix({ prefix });
    }
  });

  test('allocates an IP', async ({ adminPage, sdk }) => {
    const poolId = await somePoolId(sdk);
    const deviceId = `e2e-dev-${suffix()}`;
    const hostname = `e2e-node-${suffix()}`;
    await openPage(adminPage);

    await adminPage.getByLabel('Pool ID').fill(poolId);
    await adminPage.getByLabel('Device ID').fill(deviceId);
    await adminPage.getByLabel('Hostname').fill(hostname);
    const response = waitFor(adminPage, ALLOCATIONS_API, 'POST');
    await adminPage.getByRole('button', { name: 'Allocate' }).click();
    const ok = await accepted(await response);

    const table = adminPage.getByRole('table', { name: 'IP allocations' });
    if (ok) {
      await expect(adminPage.getByText('IP allocated').first()).toBeVisible();
      const listed = await gw(sdk).listAllocations();
      expect(listed.success, JSON.stringify(listed.error)).toBe(true);
      const mine = rows(listed.data, 'allocations').find((a) => field(a, 'deviceId', 'device_id') === deviceId);
      expect(mine, `allocation for ${deviceId} listed by the server`).toBeTruthy();
      const ip = field(mine as Raw, 'ip');
      const row = table.getByRole('row', { name: new RegExp(escapeRe(ip)) });
      await expect(row).toContainText(hostname);
      await expect(row).toContainText(deviceId);
      await gw(sdk).releaseIP({ ip });
    } else {
      await expect(adminPage.getByText('Request failed').first()).toBeVisible();
      await expect(table.getByRole('row', { name: new RegExp(escapeRe(deviceId)) })).toHaveCount(0);
    }
  });

  test('allocate needs a device id', async ({ adminPage }) => {
    const posts: string[] = [];
    adminPage.on('request', (r) => {
      if (r.method() === 'POST' && r.url().includes(ALLOCATIONS_API)) posts.push(r.url());
    });
    await openPage(adminPage);

    await adminPage.getByLabel('Pool ID').fill(`e2e-pool-${suffix()}`);
    await adminPage.getByLabel('Hostname').fill('e2e-node');
    await expect(adminPage.getByRole('button', { name: 'Allocate' })).toBeDisabled();
    expect(posts).toHaveLength(0);
  });

  test('releases an IP after confirming', async ({ adminPage, sdk }) => {
    const poolId = await somePoolId(sdk);
    const seeded = await gw(sdk).allocateIP({ poolId, deviceId: `e2e-dev-${suffix()}`, hostname: 'e2e-node' });
    branch('allocate', seeded);
    const seededIp = seeded.success && seeded.data?.allocation ? field(seeded.data.allocation, 'ip') : '';
    await openPage(adminPage);

    const table = adminPage.getByRole('table', { name: 'IP allocations' });
    if (!seededIp) {
      // No allocation was made, so the page offers only what the server lists.
      await expectSection(adminPage, ALLOCATIONS, await gw(sdk).listAllocations(), 'allocations');
      return;
    }

    const release = table.getByRole('button', { name: `Release ${seededIp}` });
    await release.click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText(`Release ${seededIp}`);
    const response = waitFor(adminPage, ALLOCATIONS_API, 'DELETE');
    await dialog.getByRole('button', { name: 'Confirm' }).click();
    const ok = await accepted(await response);

    const listed = await gw(sdk).listAllocations();
    const onServer = rows(listed.data, 'allocations').map((a) => field(a, 'ip'));
    if (ok) {
      await expect(adminPage.getByText('IP released').first()).toBeVisible();
      await expect(release).toHaveCount(0);
      expect(onServer).not.toContain(seededIp);
    } else {
      await expect(adminPage.getByText('Request failed').first()).toBeVisible();
      await gw(sdk).releaseIP({ ip: seededIp });
    }
  });

  test('lists IPAM allocations', async ({ adminPage, sdk }) => {
    const allocations = await gw(sdk).listAllocations();
    branch('IPAM allocations', allocations);
    await openPage(adminPage);

    const listed = await expectSection(adminPage, ALLOCATIONS, allocations, 'allocations');
    const table = adminPage.getByRole('table', { name: 'IP allocations' });
    for (const a of listed) {
      const row = table.getByRole('row', { name: new RegExp(escapeRe(field(a, 'ip'))) }).first();
      const host = field(a, 'hostname');
      const status = field(a, 'status');
      if (host) await expect(row).toContainText(host);
      if (status) await expect(row).toContainText(status);
    }
  });

  test('a node without a BGP speaker still lists allocations', async ({ adminPage, sdk }) => {
    const [peers, prefixes, allocations] = await Promise.all([
      gw(sdk).listBGPPeers(),
      gw(sdk).listAnnouncedPrefixes(),
      gw(sdk).listAllocations(),
    ]);
    branch('BGP peers', peers);
    branch('IPAM allocations', allocations);
    await openPage(adminPage);

    // Each section loads on its own: a BGP refusal never hides the allocations.
    await expectSection(adminPage, PEERS, peers, 'peers');
    await expectSection(adminPage, PREFIXES, prefixes, 'prefixes');
    await expectSection(adminPage, ALLOCATIONS, allocations, 'allocations');
  });

  test('a node without IPAM still lists BGP peers', async ({ adminPage, sdk }) => {
    const [allocations, peers] = await Promise.all([gw(sdk).listAllocations(), gw(sdk).listBGPPeers()]);
    branch('IPAM allocations', allocations);
    branch('BGP peers', peers);
    await openPage(adminPage);

    // Each section loads on its own: an IPAM refusal never hides the peers.
    await expectSection(adminPage, ALLOCATIONS, allocations, 'allocations');
    await expectSection(adminPage, PEERS, peers, 'peers');
  });
});
