import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';

/**
 * Capability gates against the real platformd (#2033 item 5, epic #1665).
 *
 * The issue's acceptance: one spec, run against the real-server harness,
 * checks that a disabled service greys out its controls. The harness daemon
 * creates a zone-only SDN service when no OVS socket is configured, so the
 * spec does not assume SDN is dark: it follows the daemon's answer for each
 * SDN control. The disabled service is the KV store: the quicbaas KV stub
 * ops are always reported `enabled: false` with the reason
 * `blocked: integration`, in every harness. The DNS zone create stays
 * offered (the harness config has a dns: section). No mocked routes: each
 * page reads the capabilities from the daemon itself, and each assertion
 * compares the control with what the daemon answered the SDK.
 */

interface CapabilityEntry {
  op: string;
  enabled: boolean;
  reason?: string;
}

async function capabilityList(sdk: PlatformClient): Promise<CapabilityEntry[]> {
  const res = await sdk.capabilities.list();
  expect(res.success, `capabilities.list: ${JSON.stringify(res.error)}`).toBeTruthy();
  return res.data?.capabilities ?? [];
}

function entry(caps: CapabilityEntry[], op: string): CapabilityEntry {
  const found = caps.find((c) => c.op === op);
  expect(found, `the capabilities list has no entry for ${op}`).toBeDefined();
  return found!;
}

const SDN_CONTROLS = [
  { op: 'POST /api/v1/sdn/bridges', path: '/networking/sdn', label: 'Create Network' },
  { op: 'POST /api/v1/sdn/bridges/{bridge_id}/vlans', path: '/networking/vlans', label: 'Create VLAN' },
  { op: 'POST /api/v1/sdn/bridges/{name}/flows', path: '/networking/flows', label: 'Add Flow Rule' },
];

const KV_LIST_OP = 'GET /api/v1/quicbaas/kv';
const KV_PUT_OP = 'POST /api/v1/quicbaas/kv';
const STUB_REASON = 'blocked: integration';

test.describe('Capability gates against the real platformd', () => {
  test("the SDN create controls follow the server's answer", async ({ adminPage, sdk }) => {
    const caps = await capabilityList(sdk);
    for (const control of SDN_CONTROLS) {
      const cap = entry(caps, control.op);

      await adminPage.goto(control.path);
      const button = adminPage.getByRole('button', { name: control.label, exact: true });
      await expect(button).toHaveAttribute('data-capability-enabled', String(cap.enabled));
      if (cap.enabled) {
        await expect(button).toBeEnabled();
        await expect(button).not.toHaveAttribute('title');
      } else {
        await expect(button).toBeDisabled();
        await expect(button).toHaveAttribute('title', cap.reason ?? '');
      }
    }
  });

  test('a disabled service greys out its controls: the KV store', async ({ adminPage, sdk }) => {
    const caps = await capabilityList(sdk);
    const list = entry(caps, KV_LIST_OP);
    const put = entry(caps, KV_PUT_OP);
    expect(list.enabled, `${KV_LIST_OP} is offered`).toBe(false);
    expect(list.reason).toBe(STUB_REASON);
    expect(put.enabled, `${KV_PUT_OP} is offered`).toBe(false);
    expect(put.reason).toBe(STUB_REASON);

    await adminPage.goto('/storage/kv');
    const card = adminPage.getByTestId('kv-not-enabled');
    await expect(card).toBeVisible();
    await expect(card).toContainText(list.reason!);

    const add = adminPage.getByRole('button', { name: 'Add Entry', exact: true });
    await expect(add).toBeDisabled();
    await expect(add).toHaveAttribute('data-capability-enabled', 'false');
    await expect(add).toHaveAttribute('title', put.reason!);
  });

  test('a configured DNS service leaves Add Zone enabled', async ({ adminPage, sdk }) => {
    const caps = await capabilityList(sdk);
    expect(entry(caps, 'POST /api/v1/dns/zones').enabled).toBe(true);

    await adminPage.goto('/networking/dns');
    const add = adminPage.getByRole('button', { name: 'Add Zone', exact: true });
    await expect(add).toHaveAttribute('data-capability-enabled', 'true');
    await expect(add).toBeEnabled();
    await expect(add).not.toHaveAttribute('title');
  });
});
