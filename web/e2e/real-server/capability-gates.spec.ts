import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';

/**
 * Capability gates against the real platformd (#2033 item 5, epic #1665).
 *
 * The issue's acceptance: one spec, run against the real-server harness,
 * checks that a disabled service greys out its controls. The harness config
 * (platformd.test.yaml) has no sdn: section, so the server reports the SDN
 * routes dark with a not-configured reason; it has a dns: section, so the
 * DNS zone create stays offered. No page.route: each page reads the
 * capabilities from the daemon itself, and each assertion compares the
 * control with what the daemon answered the SDK.
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

test.describe('Capability gates against the real platformd', () => {
  test('an unconfigured SDN service greys out its create controls', async ({ adminPage, sdk }) => {
    const caps = await capabilityList(sdk);
    for (const control of SDN_CONTROLS) {
      const cap = entry(caps, control.op);
      expect(cap.enabled, `${control.op} is offered`).toBe(false);
      expect(cap.reason ?? '').toMatch(/^not-configured: /);

      await adminPage.goto(control.path);
      const button = adminPage.getByRole('button', { name: control.label, exact: true });
      await expect(button).toBeDisabled();
      await expect(button).toHaveAttribute('data-capability-enabled', 'false');
      await expect(button).toHaveAttribute('title', cap.reason!);
    }
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
