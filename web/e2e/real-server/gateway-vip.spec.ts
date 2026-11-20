// Real-server spec for epic #1665 row #2052 (GatewayService VIP, load
// balancer, NAT64 and perf operations). State is seeded through the SDK
// against the harness server; every assertion reads what the server returns.
import { test, expect } from './fixtures';

const VIP_ADDRESS = '198.51.100.20';
const VIP_PORT = 8443;

test.describe('gateway VIPs (real server)', () => {
  test('ListVIPs view shows a VIP added through the SDK', async ({ adminPage, sdk }) => {
    const added = await sdk.gateway.addVIP({
      address: VIP_ADDRESS,
      port: VIP_PORT,
      protocol: 'tcp',
      backends: [{ address: '10.0.0.11', port: 443 }],
    });
    expect(added.success).toBe(true);

    const listed = await sdk.gateway.listVIPs();
    expect(listed.success).toBe(true);
    const vips = listed.data?.vips ?? [];
    expect(vips.some((v) => v.vip?.address === VIP_ADDRESS)).toBe(true);

    await adminPage.goto('/networking/gateway/vips');
    await expect(adminPage.getByRole('heading', { name: 'Virtual IPs' })).toBeVisible();
    await expect(adminPage.getByText(VIP_ADDRESS)).toBeVisible();

    await sdk.gateway.removeVIP(VIP_ADDRESS, VIP_PORT, 'tcp');
  });

  test('GetVIP detail and SetVIPBackends round-trip', async ({ adminPage, sdk }) => {
    await sdk.gateway.addVIP({
      address: VIP_ADDRESS,
      port: VIP_PORT,
      protocol: 'tcp',
      backends: [{ address: '10.0.0.11', port: 443 }],
    });

    const set = await sdk.gateway.setVIPBackends({
      address: VIP_ADDRESS,
      port: VIP_PORT,
      protocol: 'tcp',
      backends: [
        { address: '10.0.0.11', port: 443 },
        { address: '10.0.0.12', port: 443 },
      ],
    });
    expect(set.success).toBe(true);

    const got = await sdk.gateway.getVIP(VIP_ADDRESS, VIP_PORT, 'tcp');
    expect(got.success).toBe(true);
    expect(got.data?.vip?.backends?.length).toBe(2);

    await adminPage.goto('/networking/gateway/vips');
    await adminPage.getByRole('button', { name: `Backends of ${VIP_ADDRESS}:${VIP_PORT}` }).click();
    await expect(adminPage.getByText('10.0.0.12')).toBeVisible();

    await sdk.gateway.removeVIP(VIP_ADDRESS, VIP_PORT, 'tcp');
  });

  test('AddVIP and RemoveVIP through the page', async ({ adminPage, sdk }) => {
    await adminPage.goto('/networking/gateway/vips');
    await adminPage.getByLabel('VIP address').fill(VIP_ADDRESS);
    await adminPage.getByLabel('VIP port').fill(String(VIP_PORT));
    await adminPage.getByLabel('Backends').fill('10.0.0.11:443');
    await adminPage.getByRole('button', { name: 'Add VIP' }).click();
    await expect(adminPage.getByText(VIP_ADDRESS)).toBeVisible();

    const afterAdd = await sdk.gateway.listVIPs();
    expect((afterAdd.data?.vips ?? []).some((v) => v.vip?.address === VIP_ADDRESS)).toBe(true);

    await adminPage.getByRole('button', { name: `Remove ${VIP_ADDRESS}:${VIP_PORT}` }).click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    await expect(adminPage.getByText(VIP_ADDRESS)).toHaveCount(0);

    const afterRemove = await sdk.gateway.listVIPs();
    expect((afterRemove.data?.vips ?? []).some((v) => v.vip?.address === VIP_ADDRESS)).toBe(false);
  });
});

test.describe('gateway LB, NAT64 and perf status (real server)', () => {
  test('GetLBStatus and GetNAT64Status render what the server reports', async ({ adminPage, sdk }) => {
    const lb = await sdk.gateway.getLBStatus();
    const nat64 = await sdk.gateway.getNAT64Status();

    await adminPage.goto('/networking/gateway/vips');
    const lbCard = adminPage.getByTestId('gateway-lb-status');
    const natCard = adminPage.getByTestId('gateway-nat64-status');
    await expect(lbCard).toBeVisible();
    await expect(natCard).toBeVisible();
    if (!lb.success) await expect(lbCard).toContainText('unavailable');
    if (!nat64.success) await expect(natCard).toContainText('unavailable');
  });

  test('GetPerfFlows, GetPerfDatapath and GetPerfConntrack render on the perf page', async ({ adminPage, sdk }) => {
    const flows = await sdk.gateway.getPerfFlows();
    const datapath = await sdk.gateway.getPerfDatapath();
    const conntrack = await sdk.gateway.getPerfConntrack();

    await adminPage.goto('/networking/gateway/perf');
    await expect(adminPage.getByRole('heading', { name: 'Gateway performance' })).toBeVisible();
    for (const [id, resp] of [
      ['gateway-perf-flows', flows],
      ['gateway-perf-datapath', datapath],
      ['gateway-perf-conntrack', conntrack],
    ] as const) {
      const card = adminPage.getByTestId(id);
      await expect(card).toBeVisible();
      if (!resp.success) await expect(card).toContainText('unavailable');
    }
  });
});
