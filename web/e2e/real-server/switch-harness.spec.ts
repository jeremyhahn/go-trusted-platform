import { expect, test } from './fixtures';

/**
 * SwitchService against the real platformd (#2066, epic #1665).
 *
 * The test daemon config (platformd.test.yaml, `switches:`) declares
 * harness-1 on the in-memory switch vendor: Eth1/1-4 access ports on VLAN 10
 * and Eth1/5 a trunk carrying VLANs 10 and 20. Each test drives one of the
 * five SwitchService operations through the SDK (ListPorts, GetPortStatus,
 * EnablePort, DisablePort, SetPortVLAN) and puts every port it changes back.
 *
 * The memory vendor keeps one state for the daemon, so the tests run in
 * order: a port one test changes is never read by another mid-change.
 */
test.describe.configure({ mode: 'serial' });

const SWITCH = 'harness-1';

test.describe('SwitchService on the memory switch harness-1', () => {
  test('ListPorts lists the five seeded ports', async ({ sdk }) => {
    const res = await sdk.switches.listPorts(SWITCH);
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const ports = res.data ?? [];
    expect(ports.map((p) => p.port).sort()).toEqual(['Eth1/1', 'Eth1/2', 'Eth1/3', 'Eth1/4', 'Eth1/5']);
    for (const name of ['Eth1/1', 'Eth1/2', 'Eth1/3', 'Eth1/4']) {
      const port = ports.find((p) => p.port === name);
      expect(port, name).toMatchObject({ mode: 'access', access_vlan: 10, enabled: true, link_up: true });
    }
    const trunk = ports.find((p) => p.port === 'Eth1/5');
    expect(trunk).toMatchObject({ mode: 'trunk', enabled: true, link_up: true });
    expect(trunk?.trunk_vlans).toEqual([10, 20]);
  });

  test('GetPortStatus reads one port', async ({ sdk }) => {
    const res = await sdk.switches.getPortStatus(SWITCH, 'Eth1/3');
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    expect(res.data).toMatchObject({
      port: 'Eth1/3',
      mode: 'access',
      access_vlan: 10,
      enabled: true,
      link_up: true,
    });
  });

  test('DisablePort then EnablePort round-trips Eth1/2', async ({ sdk }) => {
    const port = 'Eth1/2';
    try {
      const disabled = await sdk.switches.disablePort(SWITCH, port);
      expect(disabled.success, JSON.stringify(disabled.error)).toBeTruthy();
      expect(disabled.data).toMatchObject({ action: 'disable', status: 'ok' });

      const off = await sdk.switches.getPortStatus(SWITCH, port);
      expect(off.success, JSON.stringify(off.error)).toBeTruthy();
      expect(off.data?.enabled).toBe(false);

      const enabled = await sdk.switches.enablePort(SWITCH, port);
      expect(enabled.success, JSON.stringify(enabled.error)).toBeTruthy();
      expect(enabled.data).toMatchObject({ action: 'enable', status: 'ok' });

      const on = await sdk.switches.getPortStatus(SWITCH, port);
      expect(on.success, JSON.stringify(on.error)).toBeTruthy();
      expect(on.data?.enabled).toBe(true);
    } finally {
      await sdk.switches.enablePort(SWITCH, port);
    }
  });

  test('SetPortVLAN moves Eth1/1 to VLAN 20 and back', async ({ sdk }) => {
    const port = 'Eth1/1';
    try {
      const moved = await sdk.switches.setPortVLAN(SWITCH, port, 20);
      expect(moved.success, JSON.stringify(moved.error)).toBeTruthy();
      expect(moved.data?.vlan_id).toBe(20);

      const status = await sdk.switches.getPortStatus(SWITCH, port);
      expect(status.success, JSON.stringify(status.error)).toBeTruthy();
      expect(status.data?.access_vlan).toBe(20);
    } finally {
      await sdk.switches.setPortVLAN(SWITCH, port, 10);
    }
    const back = await sdk.switches.getPortStatus(SWITCH, port);
    expect(back.data?.access_vlan).toBe(10);
  });

  test('an unknown port is refused', async ({ sdk }) => {
    const status = await sdk.switches.getPortStatus(SWITCH, 'Eth9/9');
    expect(status.success).toBe(false);
    const enabled = await sdk.switches.enablePort(SWITCH, 'Eth9/9');
    expect(enabled.success).toBe(false);
  });

  test('an unknown switch is refused', async ({ sdk }) => {
    const res = await sdk.switches.listPorts(`e2e-unmanaged-${Date.now().toString(36)}`);
    expect(res.success).toBe(false);
  });
});
