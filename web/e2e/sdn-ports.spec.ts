import { test, expect, Page, Route } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockTenantApi } from './fixtures/api-mock';

/**
 * SDN bridge detail, port state, port auth, port stats and policies (#1745).
 * Every operation is driven from /networking/sdn/[bridge] with mocked API responses.
 */

interface Call {
  method: string;
  path: string;
  body: unknown;
}

const BRIDGE = {
  id: 'br-1',
  config: { name: 'br-int', type: 'BRIDGE_TYPE_OVS' },
  status: 'BRIDGE_STATUS_UP',
  createdAt: '2026-11-01T00:00:00Z',
  updatedAt: '2026-11-01T00:00:00Z',
};

const PORT = {
  id: 'p-1',
  bridgeId: 'br-1',
  config: { name: 'eth1' },
  status: 'PORT_STATUS_UP',
  auth: { authenticated: false },
};

const POLICY = {
  id: 'pol-1',
  config: { name: 'deny-telnet', description: 'Drop telnet', type: 'POLICY_TYPE_ACL', rules: [{ ruleId: 'r1' }] },
  status: 'POLICY_STATUS_ACTIVE',
  hitCount: '42',
};

async function mockSdnApi(page: Page): Promise<Call[]> {
  const calls: Call[] = [];
  await page.route('**/api/v1/sdn/**', async (route: Route) => {
    const request = route.request();
    const method = request.method();
    const path = new URL(request.url()).pathname.replace(/^.*\/api\/v1\/sdn/, '');
    let body: unknown = null;
    try {
      body = request.postDataJSON();
    } catch {
      body = request.postData();
    }
    calls.push({ method, path, body });

    const reply = (data: unknown, status = 200) =>
      route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });

    if (path === '/bridges' && method === 'GET') return reply({ bridges: [BRIDGE] });
    if (path === '/bridges/br-1' && method === 'GET') return reply({ bridge: BRIDGE });
    if (path === '/bridges/br-1' && method === 'DELETE') return reply({ status: { success: true } });
    if (path === '/bridges/br-1/ports' && method === 'GET') return reply({ ports: [PORT] });
    if (path === '/bridges/br-1/flows' && method === 'GET') return reply({ flows: [] });
    if (path === '/bridges/br-1/ports/p-1/state' && method === 'GET') return reply({ port: PORT });
    if (path === '/bridges/br-1/ports/p-1/state' && method === 'PUT') {
      return reply({ status: { success: true }, port: { ...PORT, status: 'PORT_STATUS_DOWN' } });
    }
    if (path === '/bridges/br-1/ports/p-1/stats' && method === 'GET') {
      return reply({
        stats: {
          packetsReceived: '1234',
          packetsSent: '567',
          bytesReceived: '89000',
          bytesSent: '4500',
          errors: '3',
          dropped: '7',
        },
      });
    }
    if (path === '/bridges/br-1/ports/p-1/auth' && method === 'POST') {
      return reply({ status: { success: true }, auth: { authenticated: true } });
    }
    if (path === '/bridges/br-1/ports/p-1/auth' && method === 'DELETE') {
      return reply({ status: { success: true } });
    }
    if (path === '/policies' && method === 'GET') return reply({ policies: [POLICY] });
    if (path === '/policies' && method === 'POST') {
      return reply({ status: { success: true }, policy: { id: 'pol-2' } }, 201);
    }
    if (path === '/policies/pol-1' && method === 'GET') return reply({ policy: POLICY });
    return reply({ message: `unmocked ${method} ${path}`, code: 'NOT_FOUND' }, 404);
  });
  return calls;
}

function called(calls: Call[], method: string, path: string): Call | undefined {
  return calls.find((c) => c.method === method && c.path === path);
}

async function openBridge(page: Page): Promise<Call[]> {
  await createTenantOwnerSession(page.context());
  await mockTenantApi(page);
  const calls = await mockSdnApi(page);
  await page.goto('/networking/sdn/br-1/');
  await expect(page.getByRole('heading', { name: 'br-int' })).toBeVisible();
  return calls;
}

async function openPort(page: Page): Promise<Call[]> {
  const calls = await openBridge(page);
  await page.getByRole('button', { name: 'Manage port eth1' }).click();
  await expect(page.getByTestId('port-panel')).toBeVisible();
  return calls;
}

test.describe('SDN bridge detail and ports', () => {
  test('GetBridge shows the bridge detail', async ({ page }) => {
    const calls = await openBridge(page);
    await expect(page.getByTestId('bridge-id')).toHaveText('br-1');
    await expect(page.getByText('BRIDGE_STATUS_UP')).toBeVisible();
    expect(called(calls, 'GET', '/bridges/br-1')).toBeTruthy();
  });

  test('the bridge list links to the bridge detail', async ({ page }) => {
    await createTenantOwnerSession(page.context());
    await mockTenantApi(page);
    await mockSdnApi(page);
    await page.goto('/networking/sdn');
    await page.getByRole('link', { name: 'br-int' }).click();
    await expect(page).toHaveURL(/\/networking\/sdn\/br-1\/?$/);
    await expect(page.getByTestId('bridge-id')).toHaveText('br-1');
  });

  test('DeleteBridge deletes the bridge after confirmation', async ({ page }) => {
    const calls = await openBridge(page);
    await page.getByRole('button', { name: 'Delete Bridge' }).click();
    await expect(page.getByRole('dialog')).toContainText('Delete bridge br-1?');
    expect(called(calls, 'DELETE', '/bridges/br-1')).toBeUndefined();
    await page.getByRole('button', { name: 'Confirm Delete' }).click();
    await expect.poll(() => !!called(calls, 'DELETE', '/bridges/br-1')).toBe(true);
    await expect(page).toHaveURL(/\/networking\/sdn\/?$/);
  });

  test('GetPort shows the port state', async ({ page }) => {
    const calls = await openPort(page);
    await expect(page.getByTestId('port-state')).toContainText('PORT_STATUS_UP');
    await expect(page.getByTestId('port-state')).toContainText('Authenticated: no');
    expect(called(calls, 'GET', '/bridges/br-1/ports/p-1/state')).toBeTruthy();
  });

  test('SetPortState changes the port state', async ({ page }) => {
    const calls = await openPort(page);
    await page.getByLabel('Admin state').selectOption('down');
    await page.getByRole('button', { name: 'Set State' }).click();
    await expect.poll(() => called(calls, 'PUT', '/bridges/br-1/ports/p-1/state')?.body).toEqual({
      adminState: 'down',
    });
    await expect(page.getByText('Port state updated').first()).toBeVisible();
  });

  test('AuthenticatePort authenticates a port', async ({ page }) => {
    const calls = await openPort(page);
    await page.getByLabel('Certificate (PEM)').fill('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----');
    await page.getByRole('button', { name: 'Authenticate Port' }).click();
    await expect.poll(() => called(calls, 'POST', '/bridges/br-1/ports/p-1/auth')?.body).toEqual({
      certificate: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
      format: 'PEM',
    });
    await expect(page.getByText('Port authenticated').first()).toBeVisible();
  });

  test('RevokePortAuth revokes port auth after confirmation', async ({ page }) => {
    const calls = await openPort(page);
    await page.getByRole('button', { name: 'Revoke Auth' }).click();
    await expect(page.getByRole('dialog')).toContainText('Revoke authentication of port p-1?');
    expect(called(calls, 'DELETE', '/bridges/br-1/ports/p-1/auth')).toBeUndefined();
    await page.getByRole('button', { name: 'Confirm Revoke' }).click();
    await expect.poll(() => !!called(calls, 'DELETE', '/bridges/br-1/ports/p-1/auth')).toBe(true);
    await expect(page.getByText('Port authentication revoked').first()).toBeVisible();
  });

  test('GetPortStats shows port counters', async ({ page }) => {
    const calls = await openPort(page);
    const stats = page.getByTestId('port-stats');
    await expect(stats).toContainText('Packets received: 1234');
    await expect(stats).toContainText('Bytes sent: 4500');
    await expect(stats).toContainText('Dropped: 7');
    expect(called(calls, 'GET', '/bridges/br-1/ports/p-1/stats')).toBeTruthy();
  });

  test('ApplyPolicy applies a policy', async ({ page }) => {
    const calls = await openBridge(page);
    await page.getByRole('button', { name: 'Apply Policy' }).click();
    await page.getByLabel('Name *').fill('allow-ssh');
    await page.getByLabel('Type').selectOption('POLICY_TYPE_FIREWALL');
    await page.getByRole('button', { name: 'Apply', exact: true }).click();
    await expect.poll(() => called(calls, 'POST', '/policies')?.body).toEqual({
      config: { name: 'allow-ssh', type: 'POLICY_TYPE_FIREWALL', enabled: true },
    });
    await expect(page.getByText('Policy applied').first()).toBeVisible();
  });

  test('GetPolicy shows one policy', async ({ page }) => {
    const calls = await openBridge(page);
    await page.getByRole('button', { name: 'View policy deny-telnet' }).click();
    const detail = page.getByTestId('policy-detail');
    await expect(detail).toContainText('ID: pol-1');
    await expect(detail).toContainText('Rules: 1');
    await expect(detail).toContainText('Hits: 42');
    expect(called(calls, 'GET', '/policies/pol-1')).toBeTruthy();
  });

  test('ListPolicies lists policies', async ({ page }) => {
    const calls = await openBridge(page);
    await expect(page.getByRole('cell', { name: 'deny-telnet' })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'POLICY_STATUS_ACTIVE' })).toBeVisible();
    expect(called(calls, 'GET', '/policies')).toBeTruthy();
  });
});
