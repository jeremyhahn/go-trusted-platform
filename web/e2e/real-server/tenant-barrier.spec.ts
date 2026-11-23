/**
 * Real-server spec for the tenant barrier page, /tenant/barrier (#2067,
 * UI epic #1665). It runs against the real-server harness: no page.route
 * mocks. Every expectation is checked against what the server answered:
 * the barrier status read and the capabilities listing.
 */
import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

const STATUS_OP = 'GET /api/v1/tenants/{id}/barrier';
const INIT_OP = 'POST /api/v1/tenants/{id}/barrier/init';
const UNSEAL_OP = 'POST /api/v1/tenants/{id}/barrier/unseal';
const SEAL_OP = 'POST /api/v1/tenants/{id}/barrier/seal';

interface Capability {
  op: string;
  enabled: boolean;
  reason?: string;
}

interface BarrierStatus {
  tenantId?: string;
  sealed?: boolean;
  initialized?: boolean;
  strategy?: string;
  hardwareBacked?: boolean;
}

async function listCapabilities(sdk: {
  capabilities: { list: () => Promise<{ success: boolean; data?: { capabilities?: Capability[] } }> };
}): Promise<Capability[]> {
  const res = await sdk.capabilities.list();
  expect(res.success).toBeTruthy();
  return res.data?.capabilities ?? [];
}

function capabilityOf(caps: Capability[], op: string): Capability {
  return caps.find((c) => c.op === op) ?? { op, enabled: false };
}

function barrierPath(tenantId: string, suffix = ''): string {
  return `/api/v1/tenants/${tenantId}/barrier${suffix}`;
}

function barrierResponse(page: Page, method: string, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && new URL(r.url()).pathname === path,
  );
}

async function readStatus(page: Page, tenantId: string): Promise<BarrierStatus> {
  const res = await page.request.get(barrierPath(tenantId));
  expect(res.ok()).toBeTruthy();
  const { barrierStatus } = unwrapPayload<{ barrierStatus?: BarrierStatus }>(await res.json());
  return barrierStatus ?? {};
}

test.describe('Tenant barrier (real server)', () => {
  test.describe.configure({ mode: 'serial' });

  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/tenant/barrier');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('the sidebar Tenant group links to the barrier page', async ({ adminPage }) => {
    await adminPage.goto('/tenant');
    await adminPage.getByRole('link', { name: 'Barrier', exact: true }).click();
    await expect(adminPage).toHaveURL(/\/tenant\/barrier$/);
    await expect(adminPage.getByRole('heading', { name: 'Tenant barrier' })).toBeVisible();
  });

  test('shows the barrier status the server answers', async ({ adminPage, sdk, tenant }) => {
    const capabilities = await listCapabilities(sdk);
    const statusCap = capabilityOf(capabilities as Capability[], STATUS_OP);
    const card = adminPage.getByTestId('tenant-barrier-status');

    if (!statusCap.enabled) {
      const reads: string[] = [];
      adminPage.on('request', (r) => {
        if (r.method() === 'GET' && new URL(r.url()).pathname === barrierPath(tenant.id)) {
          reads.push(r.url());
        }
      });
      await adminPage.goto('/tenant/barrier');
      if (statusCap.reason) {
        await expect(adminPage.getByText(statusCap.reason)).toBeVisible();
      }
      await expect(card).toHaveCount(0);
      expect(reads).toEqual([]);
      return;
    }

    const statusRes = barrierResponse(adminPage, 'GET', barrierPath(tenant.id));
    await adminPage.goto('/tenant/barrier');
    const res = await statusRes;
    expect(res.ok()).toBeTruthy();
    const { barrierStatus } = unwrapPayload<{ barrierStatus?: BarrierStatus }>(await res.json());
    expect(barrierStatus).toBeDefined();
    await expect(card).toContainText(barrierStatus?.sealed ? 'Sealed' : 'Unsealed');
    await expect(card).toContainText(barrierStatus?.initialized ? 'Initialized' : 'Not initialized');
  });

  test('gates Initialize, Unseal and Seal as the server lists them', async ({ adminPage, sdk }) => {
    const capabilities = await listCapabilities(sdk);
    await adminPage.goto('/tenant/barrier');

    const controls: Array<[string, string]> = [
      ['Initialize', INIT_OP],
      ['Unseal', UNSEAL_OP],
      ['Seal', SEAL_OP],
    ];
    for (const [name, op] of controls) {
      const cap = capabilityOf(capabilities as Capability[], op);
      const button = adminPage.getByRole('button', { name, exact: true });
      await expect(button).toHaveAttribute('data-capability-op', op);
      await expect(button).toHaveAttribute('data-capability-enabled', cap.enabled ? 'true' : 'false');
      if (!cap.enabled) {
        await expect(button).toBeDisabled();
        if (cap.reason) {
          await expect(button).toHaveAttribute('title', cap.reason);
        }
      }
    }
  });

  test('Seal then Unseal round-trips the barrier', async ({ adminPage, sdk, tenant }) => {
    const capabilities = await listCapabilities(sdk);
    const caps = capabilities as Capability[];
    const statusOn = capabilityOf(caps, STATUS_OP).enabled;
    const sealOn = capabilityOf(caps, SEAL_OP).enabled;
    const unsealOn = capabilityOf(caps, UNSEAL_OP).enabled;
    test.skip(!statusOn || !sealOn || !unsealOn, 'the server does not enable the barrier status, seal and unseal ops');

    const before = await readStatus(adminPage, tenant.id);
    test.skip(
      !before.initialized || before.sealed === true,
      'the tenant barrier is not initialized and unsealed on this server',
    );

    const card = adminPage.getByTestId('tenant-barrier-status');
    try {
      await adminPage.goto('/tenant/barrier');
      await expect(card).toContainText('Unsealed');

      const sealRes = barrierResponse(adminPage, 'POST', barrierPath(tenant.id, '/seal'));
      await adminPage.getByRole('button', { name: 'Seal', exact: true }).click();
      expect((await sealRes).ok()).toBeTruthy();
      await expect(card).toContainText('Sealed'); // case-sensitive: "Unsealed" does not match

      // An empty key falls back to the deterministic init credential (tenant.proto).
      await expect(adminPage.locator('#tenant-barrier-unseal-key')).toHaveValue('');
      const unsealRes = barrierResponse(adminPage, 'POST', barrierPath(tenant.id, '/unseal'));
      await adminPage.getByRole('button', { name: 'Unseal', exact: true }).click();
      expect((await unsealRes).ok()).toBeTruthy();
      await expect(card).toContainText('Unsealed');
    } finally {
      const after = await readStatus(adminPage, tenant.id).catch(() => ({ sealed: true }) as BarrierStatus);
      if (after.sealed) {
        await adminPage.request.post(barrierPath(tenant.id, '/unseal'), { data: {} });
      }
    }
  });
});
