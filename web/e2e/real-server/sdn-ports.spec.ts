import { test, expect } from './fixtures';
import type { Page } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { daemonApi, type ApplyPolicyRequest } from './fixtures/daemon-api';

/**
 * SDN bridge detail, port state, port auth, port stats and policies (#1745)
 * against the real server.
 *
 * Ported from web/e2e/sdn-ports.spec.ts (#2037). The mocked spec answered
 * every route through mockSdnBridgeApi (bridge br-1, port p-1, policy
 * pol-1). Here each test seeds its own bridge and port through the `sdk`
 * fixture, drives /networking/sdn/[bridge], reads the result back from the
 * server, and deletes what it created.
 *
 * Gaps (docs/plans/1665-port-3.md): canned port counters (1234/4500/7) and
 * policy hit counts; the authenticate case uses a certificate the harness
 * has not issued, so it asserts the server's answer whichever it is.
 */

interface Seeded {
  bridgeId: string;
  bridgeName: string;
  portId: string;
  portName: string;
}

async function seedBridge(sdk: PlatformClient): Promise<Seeded> {
  const suffix = Date.now().toString(36).slice(-6);
  const bridgeName = `e2e-br-${suffix}`;
  const created = await sdk.sdn.createBridge({ config: { name: bridgeName } });
  if (!created.success || !created.data?.bridge) {
    throw new Error(`sdn.createBridge failed: ${JSON.stringify(created.error)}`);
  }
  const bridgeId = created.data.bridge.id;
  const portName = `e2e-p-${suffix}`;
  const port = await sdk.sdn.addPort({ bridgeId, config: { name: portName } });
  if (!port.success || !port.data?.port) {
    await sdk.sdn.deleteBridge(bridgeId, true);
    throw new Error(`sdn.addPort failed: ${JSON.stringify(port.error)}`);
  }
  return { bridgeId, bridgeName, portId: port.data.port.id, portName };
}

async function openBridge(page: Page, s: Seeded): Promise<void> {
  await page.goto(`/networking/sdn/${encodeURIComponent(s.bridgeId)}/`);
  await expect(page.getByRole('heading', { name: s.bridgeName })).toBeVisible();
}

async function openPort(page: Page, s: Seeded): Promise<void> {
  await openBridge(page, s);
  await page.getByRole('button', { name: `Manage port ${s.portName}` }).click();
  await expect(page.getByTestId('port-panel')).toBeVisible();
}

test.describe('SDN bridge detail and ports (real server)', () => {
  let seeded: Seeded | undefined;

  test.beforeEach(async ({ sdk }) => {
    seeded = await seedBridge(sdk);
  });

  test.afterEach(async ({ sdk }) => {
    if (seeded) await sdk.sdn.deleteBridge(seeded.bridgeId, true);
    seeded = undefined;
  });

  test('GetBridge shows the bridge detail', async ({ adminPage, sdk }) => {
    const s = seeded!;
    const res = await sdk.sdn.getBridge(s.bridgeId);
    expect(res.success).toBe(true);

    await openBridge(adminPage, s);
    await expect(adminPage.getByTestId('bridge-id')).toHaveText(s.bridgeId);
    const status = res.data?.bridge?.status;
    if (typeof status === 'string' && status) {
      await expect(adminPage.getByText(status).first()).toBeVisible();
    }
  });

  test('the bridge list links to the bridge detail', async ({ adminPage }) => {
    const s = seeded!;
    await adminPage.goto('/networking/sdn');
    await adminPage.getByRole('link', { name: s.bridgeName }).click();
    await expect(adminPage).toHaveURL(new RegExp(`/networking/sdn/${s.bridgeId}/?$`));
    await expect(adminPage.getByTestId('bridge-id')).toHaveText(s.bridgeId);
  });

  test('DeleteBridge deletes the bridge after confirmation', async ({ adminPage, sdk }) => {
    const s = seeded!;
    await openBridge(adminPage, s);
    await adminPage.getByRole('button', { name: 'Delete Bridge' }).click();
    await expect(adminPage.getByRole('dialog')).toContainText(`Delete bridge ${s.bridgeId}?`);
    expect((await sdk.sdn.getBridge(s.bridgeId)).success).toBe(true);

    await adminPage.getByRole('button', { name: 'Confirm Delete' }).click();
    await expect(adminPage).toHaveURL(/\/networking\/sdn\/?$/);
    await expect.poll(async () => (await sdk.sdn.getBridge(s.bridgeId)).success).toBe(false);
    seeded = undefined;
  });

  test('GetPort shows the port state', async ({ adminPage, sdk }) => {
    const s = seeded!;
    const res = await sdk.sdn.getPort(s.bridgeId, s.portId);
    expect(res.success).toBe(true);

    await openPort(adminPage, s);
    const state = adminPage.getByTestId('port-state');
    await expect(state).toBeVisible();
    await expect(state).toContainText('Authenticated: no');
  });

  test('SetPortState changes the port state', async ({ adminPage }) => {
    const s = seeded!;
    await openPort(adminPage, s);
    await adminPage.getByLabel('Admin state').selectOption('down');
    const put = adminPage.waitForResponse(
      (r) => r.url().includes(`/ports/${s.portId}/state`) && r.request().method() === 'PUT',
    );
    await adminPage.getByRole('button', { name: 'Set State' }).click();
    const reply = await put;
    expect(reply.request().postDataJSON()).toEqual({ adminState: 'down' });
    expect(reply.ok()).toBe(true);
    await expect(adminPage.getByText('Port state updated').first()).toBeVisible();
  });

  test('AuthenticatePort sends the certificate and shows the server answer', async ({ adminPage }) => {
    const s = seeded!;
    await openPort(adminPage, s);
    const pem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';
    await adminPage.getByLabel('Certificate (PEM)').fill(pem);
    const post = adminPage.waitForResponse(
      (r) => r.url().includes(`/ports/${s.portId}/auth`) && r.request().method() === 'POST',
    );
    await adminPage.getByRole('button', { name: 'Authenticate Port' }).click();
    const reply = await post;
    const body = reply.request().postDataJSON() as { certificate: string; format: string };
    expect(body.format).toBe('PEM');
    expect(Buffer.from(body.certificate, 'base64').toString()).toBe(pem);
    if (reply.ok()) {
      await expect(adminPage.getByText('Port authenticated').first()).toBeVisible();
    } else {
      await expect(adminPage.getByText('Port authenticated')).toHaveCount(0);
    }
  });

  test('RevokePortAuth asks for confirmation and calls the server', async ({ adminPage }) => {
    const s = seeded!;
    await openPort(adminPage, s);
    await adminPage.getByRole('button', { name: 'Revoke Auth' }).click();
    await expect(adminPage.getByRole('dialog')).toContainText(
      `Revoke authentication of port ${s.portId}?`,
    );
    const del = adminPage.waitForResponse(
      (r) => r.url().includes(`/ports/${s.portId}/auth`) && r.request().method() === 'DELETE',
    );
    await adminPage.getByRole('button', { name: 'Confirm Revoke' }).click();
    const reply = await del;
    if (reply.ok()) {
      await expect(adminPage.getByText('Port authentication revoked').first()).toBeVisible();
    } else {
      await expect(adminPage.getByText('Port authentication revoked')).toHaveCount(0);
    }
  });

  test('GetPortStats shows port counters', async ({ adminPage, sdk }) => {
    const s = seeded!;
    const res = await sdk.sdn.getPortStats(s.bridgeId, s.portId);
    expect(res.success).toBe(true);

    await openPort(adminPage, s);
    const stats = adminPage.getByTestId('port-stats');
    await expect(stats).toContainText('Packets received:');
    await expect(stats).toContainText('Bytes sent:');
    await expect(stats).toContainText('Dropped:');
  });

  test.describe('policies', () => {
    const created: string[] = [];

    test.afterEach(async ({ adminPage }) => {
      const api = daemonApi(adminPage);
      const res = await api.listPolicies();
      for (const p of res.data?.policies ?? []) {
        if (created.includes(p.config?.name ?? '')) {
          await api.applyPolicy({ policyId: p.id, config: { ...p.config!, enabled: false } });
        }
      }
    });

    test('ApplyPolicy applies a policy', async ({ adminPage }) => {
      const api = daemonApi(adminPage);
      const s = seeded!;
      const name = `allow-ssh-${Date.now().toString(36).slice(-6)}`;
      created.push(name);
      await openBridge(adminPage, s);
      await adminPage.getByRole('button', { name: 'Apply Policy' }).click();
      await adminPage.getByLabel('Name *').fill(name);
      await adminPage.getByLabel('Type', { exact: true }).selectOption('POLICY_TYPE_FIREWALL');
      await expect(adminPage.getByRole('button', { name: 'Apply', exact: true })).toBeDisabled();
      await adminPage.getByLabel('Action *').selectOption('POLICY_RULE_ACTION_ALLOW');
      await adminPage.getByLabel('Protocol').selectOption('tcp');
      await adminPage.getByLabel('Destination port').fill('22');
      await adminPage.getByRole('button', { name: 'Apply', exact: true }).click();
      await expect(adminPage.getByText('Policy applied').first()).toBeVisible();

      await expect
        .poll(async () => {
          const res = await api.listPolicies();
          const p = (res.data?.policies ?? []).find((x) => x.config?.name === name);
          return p ? { type: p.config?.type, targets: p.config?.targets } : undefined;
        })
        .toEqual({
          type: 'POLICY_TYPE_FIREWALL',
          targets: [{ type: 'POLICY_TARGET_TYPE_BRIDGE', id: s.bridgeId }],
        });
    });

    test('GetPolicy and ListPolicies show a seeded policy', async ({ adminPage }) => {
      const api = daemonApi(adminPage);
      const s = seeded!;
      const name = `deny-telnet-${Date.now().toString(36).slice(-6)}`;
      created.push(name);
      const applied = await api.applyPolicy({
        config: {
          name,
          type: 'POLICY_TYPE_FIREWALL',
          enabled: true,
          priority: 100,
          rules: [
            {
              ruleId: 'rule-1',
              priority: 100,
              action: 'POLICY_RULE_ACTION_DENY',
              match: { protocol: 'tcp', destinationPort: 23 },
            },
          ],
          targets: [{ type: 'POLICY_TARGET_TYPE_BRIDGE', id: s.bridgeId }],
        },
      } as ApplyPolicyRequest);
      if (!applied.success || !applied.data?.policy) {
        throw new Error(`sdn.applyPolicy failed: ${JSON.stringify(applied.error)}`);
      }
      const policyId = applied.data.policy.id;

      await openBridge(adminPage, s);
      await expect(adminPage.getByRole('cell', { name })).toBeVisible();

      await adminPage.getByRole('button', { name: `View policy ${name}` }).click();
      const detail = adminPage.getByTestId('policy-detail');
      await expect(detail).toContainText(`ID: ${policyId}`);
      await expect(detail).toContainText('Rules: 1');
      await expect(detail).toContainText('Hits:');
    });
  });
});
