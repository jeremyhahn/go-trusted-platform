import { test, expect, Page, Route, Request } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockTenantApi } from './fixtures/api-mock';

/**
 * VPN E2E tests (#1680): every VPN control-plane operation driven through
 * /networking/vpn against a stateful mock of the /api/v1/vpn routes.
 */

interface MockPeer {
  tenantId: string;
  deviceId: string;
  zones: string[];
  enrolledAtUnix: string;
}

interface MockPolicy {
  tenantId: string;
  name: string;
  module: string;
  updatedAtUnix: string;
}

interface RecordedCall {
  method: string;
  path: string;
  query: Record<string, string>;
  body: unknown;
}

interface VPNMockState {
  peers: MockPeer[];
  policies: MockPolicy[];
  /** The module GetPosturePolicy returns, by name; defaults to the listed module */
  storedModules: Record<string, string>;
  calls: RecordedCall[];
}

const NOW = '1767225600';

function gatewayStatus() {
  return {
    gatewayId: 'gw-edge-1',
    reportedAtUnix: NOW,
    reporting: true,
    running: true,
    admissions: '12',
    refusals: '3',
    lastRefusal: 'posture: disk not encrypted',
    enrolledPeers: 2,
    leasesByDataPlane: { masque: 1 },
    leases: [
      {
        id: 'lease-1',
        tenantId: 'tenant-a',
        deviceId: 'laptop-01',
        address: 'lease-addr-laptop-01',
        dataPlane: 'masque',
        zones: ['management'],
        issuedAtUnix: NOW,
        expiresAtUnix: NOW,
        renewals: 0,
      },
    ],
    posturePolicyErrors: ['tenant-a/broken: rego_parse_error'],
    rejectedPeers: [{ tenantId: 'tenant-a', deviceId: 'rogue-09', reason: 'not enrolled' }],
    revocations: {},
    postureViolations: {},
    reattest: null,
  };
}

async function fulfillJSON(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function mockVPNApi(page: Page, init: Partial<VPNMockState> = {}): Promise<VPNMockState> {
  const state: VPNMockState = {
    peers: init.peers ?? [
      { tenantId: 'tenant-a', deviceId: 'laptop-01', zones: ['management'], enrolledAtUnix: NOW },
      { tenantId: 'tenant-a', deviceId: 'phone-02', zones: [], enrolledAtUnix: NOW },
    ],
    policies: init.policies ?? [
      { tenantId: 'tenant-a', name: 'disk-encryption', module: 'package vpn.posture\n', updatedAtUnix: NOW },
    ],
    storedModules: init.storedModules ?? {},
    calls: [],
  };

  await page.route('**/api/v1/vpn/**', async (route: Route, request: Request) => {
    const url = new URL(request.url());
    const path = url.pathname.replace(/\/+$/, '').replace(/^.*\/api\/v1\/vpn/, '');
    const query = Object.fromEntries(url.searchParams.entries());
    const method = request.method();
    let body: unknown = null;
    const raw = request.postData();
    if (raw) {
      body = JSON.parse(raw);
    }
    state.calls.push({ method, path, query, body });

    if (path === '/status' && method === 'GET') {
      return fulfillJSON(route, { gateways: [gatewayStatus()] });
    }
    if (path === '/peers' && method === 'GET') {
      return fulfillJSON(route, { peers: state.peers });
    }
    if (path === '/peers' && method === 'POST') {
      const req = body as { tenantId: string; deviceId: string; zones?: string[] };
      const peer: MockPeer = {
        tenantId: req.tenantId,
        deviceId: req.deviceId,
        zones: req.zones ?? [],
        enrolledAtUnix: NOW,
      };
      state.peers = [
        ...state.peers.filter((p) => !(p.tenantId === peer.tenantId && p.deviceId === peer.deviceId)),
        peer,
      ];
      return fulfillJSON(route, { peer });
    }
    const peerMatch = path.match(/^\/peers\/([^/]+)$/);
    if (peerMatch && method === 'DELETE') {
      const deviceId = decodeURIComponent(peerMatch[1]);
      state.peers = state.peers.filter((p) => !(p.tenantId === query.tenant_id && p.deviceId === deviceId));
      return fulfillJSON(route, {});
    }
    if (path === '/posture-policies' && method === 'GET') {
      return fulfillJSON(route, { policies: state.policies });
    }
    const policyMatch = path.match(/^\/posture-policies\/([^/]+)$/);
    if (policyMatch) {
      const name = decodeURIComponent(policyMatch[1]);
      if (method === 'GET') {
        const policy = state.policies.find((p) => p.tenantId === query.tenant_id && p.name === name);
        if (!policy) {
          return fulfillJSON(route, { message: 'not found', code: 'NOT_FOUND' }, 404);
        }
        return fulfillJSON(route, {
          policy: { ...policy, module: state.storedModules[name] ?? policy.module },
        });
      }
      if (method === 'PUT') {
        const req = body as { tenantId: string; module: string };
        const policy: MockPolicy = { tenantId: req.tenantId, name, module: req.module, updatedAtUnix: NOW };
        state.policies = [
          ...state.policies.filter((p) => !(p.tenantId === policy.tenantId && p.name === name)),
          policy,
        ];
        return fulfillJSON(route, { policy });
      }
      if (method === 'DELETE') {
        state.policies = state.policies.filter((p) => !(p.tenantId === query.tenant_id && p.name === name));
        return fulfillJSON(route, {});
      }
    }
    return fulfillJSON(route, { message: `unmocked ${method} ${path}`, code: 'UNMOCKED' }, 500);
  });

  return state;
}

function callsTo(state: VPNMockState, method: string, path: string): RecordedCall[] {
  return state.calls.filter((c) => c.method === method && c.path === path);
}

async function openVPNPage(page: Page, init: Partial<VPNMockState> = {}): Promise<VPNMockState> {
  await createTenantOwnerSession(page.context());
  await mockTenantApi(page);
  const state = await mockVPNApi(page, init);
  await page.goto('/networking/vpn');
  await expect(page.getByRole('heading', { name: 'VPN', exact: true })).toBeVisible();
  return state;
}

test.describe('VPN peers and posture policies', () => {
  test('lists peers', async ({ page }) => {
    const state = await openVPNPage(page);

    await expect(page.getByText('Enrolled Peers')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Revoke laptop-01' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Revoke phone-02' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'all allowed' })).toBeVisible();
    expect(callsTo(state, 'GET', '/peers').length).toBeGreaterThan(0);
  });

  test('enrols a peer', async ({ page }) => {
    const state = await openVPNPage(page);

    await page.getByRole('button', { name: 'Enrol Peer' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: 'Enrol VPN Peer' })).toBeVisible();
    const submit = dialog.getByRole('button', { name: 'Enrol', exact: true });
    await expect(submit).toBeDisabled();

    await dialog.locator('#vpn-peer-tenant').fill('tenant-b');
    await dialog.locator('#vpn-peer-device').fill('desktop-03');
    await dialog.locator('#vpn-peer-zones').fill('management, storage');
    await submit.click();

    await expect(dialog).toBeHidden();
    await expect(page.getByRole('button', { name: 'Revoke desktop-03' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'management, storage' })).toBeVisible();
    const posts = callsTo(state, 'POST', '/peers');
    expect(posts).toHaveLength(1);
    expect(posts[0].body).toEqual({ tenantId: 'tenant-b', deviceId: 'desktop-03', zones: ['management', 'storage'] });
  });

  test('revokes a peer behind its confirm', async ({ page }) => {
    const state = await openVPNPage(page);

    await page.getByRole('button', { name: 'Revoke phone-02' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Revoke phone-02 of tenant tenant-a?')).toBeVisible();

    // Cancel sends nothing.
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    expect(callsTo(state, 'DELETE', '/peers/phone-02')).toHaveLength(0);

    await page.getByRole('button', { name: 'Revoke phone-02' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm Revoke' }).click();

    await expect(page.getByRole('button', { name: 'Revoke phone-02' })).toBeHidden();
    await expect(page.getByRole('button', { name: 'Revoke laptop-01' })).toBeVisible();
    const deletes = callsTo(state, 'DELETE', '/peers/phone-02');
    expect(deletes).toHaveLength(1);
    expect(deletes[0].query).toEqual({ tenant_id: 'tenant-a' });
  });

  test('shows the status card', async ({ page }) => {
    const state = await openVPNPage(page);

    await expect(page.getByRole('cell', { name: 'gw-edge-1' }).first()).toBeVisible();
    await expect(page.getByText('running', { exact: true })).toBeVisible();
    await expect(page.getByRole('cell', { name: '12', exact: true })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'posture: disk not encrypted' })).toBeVisible();
    await expect(page.getByText('gw-edge-1 refused tenant-a/rogue-09')).toBeVisible();
    await expect(page.getByText('gw-edge-1 could not load a posture policy')).toBeVisible();
    // The lease the gateway reports shows in the Sessions card.
    await expect(page.getByRole('cell', { name: 'lease-addr-laptop-01' })).toBeVisible();
    expect(callsTo(state, 'GET', '/status').length).toBeGreaterThan(0);
  });

  test('lists posture policies', async ({ page }) => {
    const state = await openVPNPage(page, {
      policies: [
        { tenantId: 'tenant-a', name: 'disk-encryption', module: 'package vpn.posture\n', updatedAtUnix: NOW },
        { tenantId: 'tenant-b', name: 'os-version', module: 'package vpn.posture\n', updatedAtUnix: NOW },
      ],
    });

    await expect(page.getByText('Posture Policies')).toBeVisible();
    await expect(page.getByRole('cell', { name: 'disk-encryption' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'os-version' })).toBeVisible();
    expect(callsTo(state, 'GET', '/posture-policies').length).toBeGreaterThan(0);
  });

  test('gets a posture policy', async ({ page }) => {
    const stored = 'package vpn.posture\n\ndeny contains "disk" if not input.disk_encrypted\n';
    const state = await openVPNPage(page, { storedModules: { 'disk-encryption': stored } });

    await page.getByRole('button', { name: 'Edit disk-encryption' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: 'Posture Policy disk-encryption' })).toBeVisible();
    // The editor shows the module GetPosturePolicy returned, not the listed one.
    await expect(dialog.locator('#vpn-policy-module')).toHaveValue(stored);
    await expect(dialog.locator('#vpn-policy-tenant')).toBeDisabled();
    await expect(dialog.locator('#vpn-policy-name')).toBeDisabled();
    const gets = callsTo(state, 'GET', '/posture-policies/disk-encryption');
    expect(gets).toHaveLength(1);
    expect(gets[0].query).toEqual({ tenant_id: 'tenant-a' });
  });

  test('sets a posture policy', async ({ page }) => {
    const state = await openVPNPage(page);
    const module = 'package vpn.posture\n\ndeny contains "os" if input.os_version < 14\n';

    await page.getByRole('button', { name: 'New Policy' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: 'New Posture Policy' })).toBeVisible();
    await dialog.locator('#vpn-policy-tenant').fill('tenant-b');
    await dialog.locator('#vpn-policy-name').fill('os-version');
    await dialog.locator('#vpn-policy-module').fill(module);
    await dialog.getByRole('button', { name: 'Save' }).click();

    await expect(dialog).toBeHidden();
    await expect(page.getByRole('cell', { name: 'os-version' })).toBeVisible();
    const puts = callsTo(state, 'PUT', '/posture-policies/os-version');
    expect(puts).toHaveLength(1);
    expect(puts[0].body).toMatchObject({ tenantId: 'tenant-b', module });

    // Editing a stored policy writes it back under the same name.
    await page.getByRole('button', { name: 'Edit disk-encryption' }).click();
    const editor = page.getByRole('dialog');
    await editor.locator('#vpn-policy-module').fill('package vpn.posture\n\ndefault allow := true\n');
    await editor.getByRole('button', { name: 'Save' }).click();
    await expect(editor).toBeHidden();
    const edits = callsTo(state, 'PUT', '/posture-policies/disk-encryption');
    expect(edits).toHaveLength(1);
    expect(edits[0].body).toMatchObject({
      tenantId: 'tenant-a',
      module: 'package vpn.posture\n\ndefault allow := true\n',
    });
  });

  test('deletes a posture policy', async ({ page }) => {
    const state = await openVPNPage(page);

    await page.getByRole('button', { name: 'Delete disk-encryption' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Delete posture policy disk-encryption of tenant tenant-a?')).toBeVisible();
    expect(callsTo(state, 'DELETE', '/posture-policies/disk-encryption')).toHaveLength(0);
    await dialog.getByRole('button', { name: 'Confirm Delete' }).click();

    await expect(dialog).toBeHidden();
    await expect(page.getByText('No posture policies are stored.')).toBeVisible();
    const deletes = callsTo(state, 'DELETE', '/posture-policies/disk-encryption');
    expect(deletes).toHaveLength(1);
    expect(deletes[0].query).toEqual({ tenant_id: 'tenant-a' });
  });
});
