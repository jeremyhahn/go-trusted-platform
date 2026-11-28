/**
 * Real-server spec for the tenant barrier page, /tenant/barrier (#2067,
 * UI epic #1665). It runs against the real-server harness: no page.route
 * mocks. Every expectation is checked against what the server answered:
 * the barrier status read and the capabilities listing. It covers both
 * tenant kinds: a tenant with no barrier (the registration fixture's default
 * prefix tenant), where the card shows "Not applicable" and disables its key
 * input and Unseal, and a barrier, volume or raft tenant, where it shows the
 * sealed and initialized state. It also drives the three mutations,
 * Initialize, Unseal and Seal, through the platform REST API against the
 * real backend, which refuses them for the prefix fixture tenant and leaves
 * its barrier status unchanged. The success lifecycle on a barrier tenant
 * (init, wrong-key refusal, seal, unseal) waits on a way to make one in the
 * harness (go-quicbaas#358); pkg/tenant unit tests cover it until then.
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
  isolation?: string;
}

// hasNoBarrier follows the card's rule (tenant-barrier-card.tsx): a status
// naming an isolation other than barrier, volume or raft has no barrier.
function hasNoBarrier(status: BarrierStatus | undefined): boolean {
  return !!status?.isolation && !['barrier', 'volume', 'raft'].includes(status.isolation);
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
    await expect(adminPage.getByRole('heading', { name: 'Tenant keys' })).toBeVisible();
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
      // The server lists a disabled op with its reason, e.g.
      // `not-configured: tenant-barrier` when no barrier backend is wired.
      expect(statusCap.reason).toBeTruthy();
      await expect(adminPage.getByText(statusCap.reason ?? '', { exact: true })).toBeVisible();
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
    if (hasNoBarrier(barrierStatus)) {
      await expect(card.getByTestId('tenant-barrier-not-applicable')).toContainText(
        `Not applicable: ${barrierStatus?.isolation} isolation`,
      );
      await expect(card).not.toContainText('Sealed');
      await expect(card).not.toContainText('Unsealed');
      await expect(card).not.toContainText('Initialized');
      await expect(card).not.toContainText('Not initialized');
      return;
    }
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

  test('keeps Unseal off until a key is typed and leaves the fixture barrier as it found it', async ({
    adminPage,
    sdk,
    tenant,
  }) => {
    const capabilities = await listCapabilities(sdk);
    const caps = capabilities as Capability[];
    const statusOn = capabilityOf(caps, STATUS_OP).enabled;
    const unsealOn = capabilityOf(caps, UNSEAL_OP).enabled;
    test.skip(!statusOn || !unsealOn, 'the server does not enable the barrier status and unseal ops');

    const before = await readStatus(adminPage, tenant.id);
    const actions = [barrierPath(tenant.id, '/unseal'), barrierPath(tenant.id, '/seal')];
    const posts: string[] = [];
    adminPage.on('request', (r) => {
      const path = new URL(r.url()).pathname;
      if (r.method() === 'POST' && actions.includes(path)) {
        posts.push(path);
      }
    });

    await adminPage.goto('/tenant/barrier');
    const key = adminPage.locator('#tenant-barrier-unseal-key');
    const unseal = adminPage.getByRole('button', { name: 'Unseal', exact: true });
    await expect(key).toHaveValue('');
    await expect(unseal).toBeDisabled();
    if (hasNoBarrier(before)) {
      // A tenant with no barrier: the card disables the key input and
      // Unseal outright, so there is nothing to type into.
      await expect(key).toBeDisabled();
    } else {
      await key.fill('a2V5');
      await expect(unseal).toBeEnabled();
      await key.fill('');
      await expect(unseal).toBeDisabled();
    }
    expect(posts).toEqual([]);

    const after = await readStatus(adminPage, tenant.id);
    expect(after.sealed).toBe(before.sealed);
  });

  test('refuses Initialize, Unseal and Seal on the fixture tenant and leaves its barrier unchanged', async ({
    adminPage,
    sdk,
    tenant,
  }) => {
    const caps = (await listCapabilities(sdk)) as Capability[];
    const statusOn = capabilityOf(caps, STATUS_OP).enabled;

    let before: BarrierStatus | undefined;
    if (statusOn) {
      before = await readStatus(adminPage, tenant.id);
      expect(
        hasNoBarrier(before),
        `the harness tenant now has a barrier (isolation ${before.isolation}): ` +
          'write the barrier lifecycle test (init, wrong-key unseal refused, seal, unseal) in place of this one',
      ).toBe(true);
    }

    // The platform REST API against the real backend, no page.route: the
    // server refuses every barrier verb for a prefix tenant.
    const verbs: Array<[string, string, Record<string, unknown>]> = [
      [INIT_OP, '/init', { passphrase: 'e2e-barrier-pass' }],
      // base64 of e2e-barrier-pass: the proto key field is bytes.
      [UNSEAL_OP, '/unseal', { key: 'ZTJlLWJhcnJpZXItcGFzcw==' }],
      [SEAL_OP, '/seal', {}],
    ];
    for (const [op, suffix, data] of verbs) {
      const res = await adminPage.request.post(barrierPath(tenant.id, suffix), { data });
      expect(res.ok(), `${op} on the fixture tenant answered ${res.status()}, want a refusal`).toBe(false);
      expect(res.status()).toBeGreaterThanOrEqual(400);
      if (capabilityOf(caps, op).enabled) {
        expect(await res.text(), `${op} refusal should name the tenant's isolation`).toContain('isolation');
      }
    }

    if (statusOn && before) {
      const after = await readStatus(adminPage, tenant.id);
      expect(after.sealed).toBe(before.sealed);
      expect(after.initialized).toBe(before.initialized);
    }
  });
});
