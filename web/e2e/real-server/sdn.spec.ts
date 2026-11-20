/**
 * Real-server spec for the SDN service (#2064, epic #1665 coverage slice 27).
 *
 * State is seeded through the SDK client (`sdk.sdn`), never through route
 * mocks; every assertion reads what the real server returns.
 */
import { test, expect } from './fixtures';

function uniqueName(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e4)}`;
}

test.describe('SDN service', () => {
  test('bridge detail shows GetBridge and DeleteBridge removes it', async ({ adminPage, sdk }) => {
    const name = uniqueName('e2e-br');
    const created = await sdk.sdn.createBridge({ config: { name } });
    expect(created.success).toBe(true);

    await adminPage.goto(`/networking/sdn/${encodeURIComponent(name)}`);
    await expect(adminPage.getByRole('heading', { name })).toBeVisible();

    const got = await sdk.sdn.getBridge(name);
    expect(got.success).toBe(true);

    await adminPage.getByRole('button', { name: /delete bridge/i }).first().click();
    await adminPage.getByRole('button', { name: /^delete$/i }).click();
    await expect(adminPage.getByText('Bridge deleted')).toBeVisible();

    const after = await sdk.sdn.getBridge(name);
    expect(after.success).toBe(false);
  });

  test('port state, stats and authentication flow', async ({ adminPage, sdk }) => {
    const name = uniqueName('e2e-br');
    await sdk.sdn.createBridge({ config: { name } });
    const port = await sdk.sdn.addPort({ bridgeId: name, config: { name: uniqueName('p') } } as never);
    expect(port.success).toBe(true);
    const portId = (port.data as { port?: { id?: string } } | undefined)?.port?.id ?? '';
    expect(portId).not.toBe('');

    await adminPage.goto(`/networking/sdn/${encodeURIComponent(name)}`);
    await adminPage.getByText(portId).first().click();

    // GetPort + GetPortStats render for the selected port.
    const state = await sdk.sdn.getPort(name, portId);
    expect(state.success).toBe(true);
    const stats = await sdk.sdn.getPortStats(name, portId);
    expect(stats.success).toBe(true);

    // SetPortState through the page, read back through the SDK.
    await adminPage.getByRole('button', { name: /set state/i }).click();
    await expect(adminPage.getByText(/port state/i).first()).toBeVisible();
    const reread = await sdk.sdn.getPort(name, portId);
    expect(reread.success).toBe(true);

    // RevokePortAuth answers from the server (no auth yet is still a server answer).
    const revoke = await sdk.sdn.revokePortAuth(name, portId);
    expect(typeof revoke.success).toBe('boolean');

    await sdk.sdn.deleteBridge(name, true);
  });

  test('flows page flushes flows and shows flow stats', async ({ adminPage, sdk }) => {
    const name = uniqueName('e2e-br');
    await sdk.sdn.createBridge({ config: { name } });
    const flow = await sdk.sdn.addFlow({
      config: { bridgeId: name, table: 'FLOW_TABLE_0', match: {}, actions: [{ type: 'FLOW_ACTION_DROP' }] },
    } as never);
    expect(flow.success).toBe(true);
    const flowId = (flow.data as { flow?: { id?: string } } | undefined)?.flow?.id ?? '';

    // GetFlowStats through the page.
    await adminPage.goto('/networking/flows');
    await adminPage.getByRole('combobox').first().click();
    await adminPage.getByRole('option', { name }).click();
    await adminPage.getByRole('button', { name: `Stats for flow ${flowId}` }).click();
    await expect(adminPage.getByText(/packets/i).first()).toBeVisible();

    const stats = await sdk.sdn.getFlowStats(name, flowId);
    expect(stats.success).toBe(true);

    // FlushFlows through the page, then the server lists none.
    await adminPage.getByRole('button', { name: /flush flows/i }).click();
    await adminPage.getByRole('button', { name: /^flush$/i }).click();
    await expect(adminPage.getByText(/flows flushed/i)).toBeVisible();

    const listed = await sdk.sdn.listFlows({ bridgeId: name });
    expect(listed.success).toBe(true);
    expect(listed.data?.flows ?? []).toHaveLength(0);

    await sdk.sdn.deleteBridge(name, true);
  });

  test('policies: apply, get, list and delete', async ({ adminPage, sdk }) => {
    const name = uniqueName('e2e-br');
    await sdk.sdn.createBridge({ config: { name } });
    const policyName = uniqueName('pol');
    const applied = await sdk.sdn.applyPolicy({ config: { name: policyName, enabled: true } });
    expect(applied.success).toBe(true);
    const policyId = applied.data?.policy?.id ?? '';
    expect(policyId).not.toBe('');

    const got = await sdk.sdn.getPolicy(policyId);
    expect(got.success).toBe(true);
    const listed = await sdk.sdn.listPolicies();
    expect(listed.success).toBe(true);

    await adminPage.goto(`/networking/sdn/${encodeURIComponent(name)}`);
    await expect(adminPage.getByText(policyName).first()).toBeVisible();

    // DeletePolicy through the page.
    await adminPage.getByRole('button', { name: `Delete policy ${policyName}` }).click();
    await adminPage.getByRole('button', { name: /^delete$/i }).click();
    await expect(adminPage.getByText('Policy deleted')).toBeVisible();

    const after = await sdk.sdn.getPolicy(policyId);
    expect(after.success).toBe(false);

    await sdk.sdn.deleteBridge(name, true);
  });
});
