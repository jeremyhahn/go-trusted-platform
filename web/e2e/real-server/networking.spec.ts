/**
 * Networking pages against the real-server harness (#2036, epic #1665).
 *
 * Ported from web/e2e/networking.spec.ts. Bridges, VLANs, DNS zones and PXE
 * devices are created through the SDK; gateway and PXE role states are read
 * from the server first and the page is held to whichever answer it gave.
 * Mocked cases with no server behaviour behind them (artificial latency,
 * injected 500s, a 409 from a create dialog that does not exist, hand-set port
 * and flow counters, a member session) are listed as gaps in the PR body.
 */
import { test, expect } from './fixtures';

interface Result<T> {
  success: boolean;
  data?: T;
  error?: unknown;
}

interface Bridge {
  id: string;
  config?: { name?: string };
  name?: string;
}

/** The part of the SDK these specs drive. */
interface NetSdk {
  sdn: {
    createBridge(req: { config: { name: string } }): Promise<Result<unknown>>;
    listBridges(): Promise<Result<{ bridges: Bridge[] }>>;
    createVLAN(req: { config: { vlanId: number; name?: string; bridgeId: string } }): Promise<Result<unknown>>;
  };
  dns: {
    createZone(req: { name: string; ttl?: number }): Promise<Result<unknown>>;
  };
  gateway: {
    getStatus(): Promise<Result<unknown>>;
    listIPAMPools(): Promise<Result<{ pools?: Array<{ cidr?: string }> }>>;
  };
  pxe: {
    getStatus(): Promise<Result<unknown>>;
    registerDevice(req: { macAddress: string }): Promise<Result<unknown>>;
    listDevices(): Promise<Result<{ devices: Array<{ macAddress: string; state?: string }> }>>;
  };
}

function suffix(): string {
  return `${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
}

/** A locally administered unicast MAC, unique per call. */
function randomMac(): string {
  const bytes = [0x02, ...Array.from({ length: 5 }, () => Math.floor(Math.random() * 256))];
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join(':');
}

function isNotConfigured(res: Result<unknown>): boolean {
  return JSON.stringify(res.error ?? {}).includes('SERVICE_NOT_CONFIGURED');
}

/** Creates an SDN bridge and returns the ID the server listed it under. */
async function createBridge(sdk: NetSdk, name: string): Promise<string> {
  const created = await sdk.sdn.createBridge({ config: { name } });
  expect(created.success, JSON.stringify(created.error)).toBe(true);
  const listed = await sdk.sdn.listBridges();
  expect(listed.success, JSON.stringify(listed.error)).toBe(true);
  const bridge = (listed.data?.bridges ?? []).find((b) => (b.config?.name ?? b.name) === name);
  expect(bridge, `bridge ${name} listed by the server`).toBeTruthy();
  return (bridge as Bridge).id;
}

test.describe('Networking Management', () => {
  test.describe('SDN VLANs', () => {
    test('shows the VLANs the server holds', async ({ adminPage, sdk }) => {
      const bridgeId = await createBridge(sdk, `br-e2e-${suffix()}`);
      const names = [`TestVLAN-${suffix()}`, `TestVLAN-${suffix()}`];
      const ids = [100 + Math.floor(Math.random() * 1000), 1200 + Math.floor(Math.random() * 1000)];
      for (let i = 0; i < names.length; i++) {
        const res = await sdk.sdn.createVLAN({ config: { vlanId: ids[i], name: names[i], bridgeId } });
        expect(res.success, JSON.stringify(res.error)).toBe(true);
      }

      await adminPage.goto('/networking/vlans');

      await expect(adminPage.getByRole('heading', { name: /vlan/i }).first()).toBeVisible();
      await expect(adminPage.getByText(/vlan id/i).first()).toBeVisible();
      for (const name of names) {
        await expect(adminPage.getByText(name)).toBeVisible();
      }
    });

    test('shows the create VLAN button', async ({ adminPage }) => {
      await adminPage.goto('/networking/vlans');

      await expect(adminPage.getByRole('heading', { name: /vlan/i }).first()).toBeVisible();
      await expect(adminPage.getByRole('button', { name: /create vlan/i })).toBeVisible();
    });
  });

  test.describe('SDN Bridges', () => {
    test('shows the bridges the server holds', async ({ adminPage, sdk }) => {
      const names = [`br-int-${suffix()}`, `br-ext-${suffix()}`];
      for (const name of names) {
        await createBridge(sdk, name);
      }

      await adminPage.goto('/networking/sdn');

      await expect(adminPage.getByRole('heading', { name: /software.defined|networking/i }).first()).toBeVisible();
      for (const name of names) {
        await expect(adminPage.getByText(name).first()).toBeVisible();
      }
    });
  });

  test.describe('SDN Ports', () => {
    test('loads the ports page', async ({ adminPage }) => {
      await adminPage.goto('/networking/ports');

      await expect(adminPage.locator('h1').filter({ hasText: /sdn ports|ports/i })).toBeVisible();
    });
  });

  test.describe('SDN Flows', () => {
    test('loads the OpenFlow rules page', async ({ adminPage }) => {
      await adminPage.goto('/networking/flows');

      await expect(adminPage.locator('h1').filter({ hasText: /openflow|flow/i })).toBeVisible();
    });
  });

  test.describe('Gateway', () => {
    test('shows the local gateway state the server reports', async ({ adminPage, sdk }) => {
      const status = await sdk.gateway.getStatus();

      await adminPage.goto('/networking/gateway');

      await expect(adminPage.getByRole('heading', { name: /gateway/i }).first()).toBeVisible();
      if (status.success) {
        await expect(adminPage.getByText(/healthy|active/i).first()).toBeVisible();
      } else if (isNotConfigured(status)) {
        await expect(adminPage.getByText(/this node does not run gatewayd/i)).toBeVisible();
        await expect(adminPage.getByText('Unhealthy')).not.toBeVisible();
        await expect(adminPage.getByText(/error loading gateway status/i)).not.toBeVisible();
      } else {
        await expect(adminPage.getByText(/error loading local gateway service/i)).toBeVisible();
        await expect(adminPage.getByText(/this node does not run gatewayd/i)).not.toBeVisible();
      }
    });

    test('shows the IPAM pools the server returns', async ({ adminPage, sdk }) => {
      const pools = await sdk.gateway.listIPAMPools();
      test.skip(!pools.success, 'the harness node runs no gatewayd, so it has no IPAM pools');

      await adminPage.goto('/networking/gateway');
      const ipamTab = adminPage.getByRole('tab', { name: /ipam|pool/i });
      if (await ipamTab.isVisible()) {
        await ipamTab.click();
      }

      for (const pool of pools.data?.pools ?? []) {
        if (pool.cidr) {
          await expect(adminPage.getByText(pool.cidr).first()).toBeVisible();
        }
      }
    });
  });

  test.describe('DNS', () => {
    test('shows the zones the server holds', async ({ adminPage, sdk }) => {
      const zones = [`e2e-example-${suffix()}.local`, `e2e-internal-${suffix()}.local`];
      for (const name of zones) {
        const res = await sdk.dns.createZone({ name, ttl: 300 });
        expect(res.success, JSON.stringify(res.error)).toBe(true);
      }

      await adminPage.goto('/networking/dns');

      await expect(adminPage.getByRole('heading', { name: /dns zones/i })).toBeVisible();
      for (const name of zones) {
        await expect(adminPage.getByText(name)).toBeVisible();
      }
    });

    test('shows the add zone button', async ({ adminPage }) => {
      await adminPage.goto('/networking/dns');

      await expect(adminPage.getByRole('heading', { name: /dns zones/i })).toBeVisible();
      await expect(adminPage.getByRole('button', { name: /add zone/i })).toBeVisible();
    });
  });

  test.describe('Overlay Networks', () => {
    test('shows the overlay statistics and create button', async ({ adminPage }) => {
      await adminPage.goto('/networking/overlays');

      await expect(adminPage.getByRole('heading', { name: /network overlays|overlay/i }).first()).toBeVisible();
      await expect(adminPage.getByText(/total overlays/i)).toBeVisible();
      await expect(adminPage.getByRole('button', { name: /create overlay/i })).toBeVisible();
    });
  });

  test.describe('PXE', () => {
    test('shows the PXE state the server reports', async ({ adminPage, sdk }) => {
      const status = await sdk.pxe.getStatus();

      await adminPage.goto('/networking/pxe');

      await expect(adminPage.locator('h1').filter({ hasText: /pxe/i })).toBeVisible();
      if (status.success) {
        await expect(adminPage.getByText(/running|stopped/i).first()).toBeVisible();
      } else if (isNotConfigured(status)) {
        await expect(adminPage.getByText(/pxe is not available on this node/i)).toBeVisible();
        await expect(adminPage.getByRole('heading', { name: /error loading pxe boot/i })).not.toBeVisible();
      } else {
        await expect(adminPage.getByRole('heading', { name: /error loading pxe boot/i })).toBeVisible();
        await expect(adminPage.getByText(/pxe is not available on this node/i)).not.toBeVisible();
      }
    });

    test('shows registered PXE devices with the state the server gave them', async ({ adminPage, sdk }) => {
      const status = await sdk.pxe.getStatus();
      test.skip(!status.success, 'PXE is not served by the harness node');

      const macs = [randomMac(), randomMac()];
      for (const macAddress of macs) {
        const res = await sdk.pxe.registerDevice({ macAddress });
        expect(res.success, JSON.stringify(res.error)).toBe(true);
      }
      const listed = await sdk.pxe.listDevices();
      expect(listed.success, JSON.stringify(listed.error)).toBe(true);

      await adminPage.goto('/networking/pxe');

      for (const mac of macs) {
        const device = (listed.data?.devices ?? []).find((d) => d.macAddress.toLowerCase() === mac);
        expect(device, `device ${mac} listed by the server`).toBeTruthy();
        await expect(adminPage.getByText(new RegExp(mac, 'i')).first()).toBeVisible();
        if (device?.state) {
          await expect(adminPage.getByText(device.state).first()).toBeVisible();
        }
      }
    });
  });

  test.describe('Access Control', () => {
    test('redirects an unauthenticated browser to login', async ({ browser }) => {
      const context = await browser.newContext();
      const page = await context.newPage();
      try {
        await page.goto('/networking/vlans');
        await expect(page).toHaveURL(/\/auth\/webauthn/);
      } finally {
        await context.close();
      }
    });
  });

  test.describe('Navigation', () => {
    for (const [path, heading] of [
      ['/networking/vlans', /vlan/i],
      ['/networking/dns', /dns/i],
      ['/networking/pxe', /pxe/i],
    ] as const) {
      test(`opens ${path} directly`, async ({ adminPage }) => {
        await adminPage.goto(path);

        await expect(adminPage.locator('h1').filter({ hasText: heading }).first()).toBeVisible();
      });
    }
  });
});
