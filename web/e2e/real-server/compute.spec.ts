import type { Locator, Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Compute pages against the real platformd (#2044, epic #1665).
 *
 * The test daemon's config (web/e2e/real-server/platformd.test.yaml) has no
 * compute section, so the server answers the compute routes with the
 * structured 503 reason SERVICE_NOT_CONFIGURED. Each test reads what the
 * server answered the page itself and asserts the page shows that: the
 * "Compute is not available on this node" state today on the VM list, the
 * snapshots list, the snapshot detail and the VM detail (no error toast or
 * alert), and the listed VMs and their links when a server answers with
 * compute configured.
 *
 * Read-only: no page.route, no writes, and no write control is clicked. Each
 * gate is checked against GET /api/v1/capabilities; an offered control is
 * never asserted enabled (the page may disable it for its own reasons).
 */

const NOT_OFFERED = 'not offered by this server';

interface Capability {
  op: string;
  kind: string;
  enabled: boolean;
  reason?: string;
}

type Capabilities = Map<string, Capability>;

interface WireVM {
  id: string;
  name?: string;
  config?: { name?: string };
}

/** Waits for the page's own GET of exactly path. */
function apiResponse(page: Page, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path,
  );
}

/** The server's capability list, keyed by op. */
async function capabilityMap(sdk: PlatformClient): Promise<Capabilities> {
  const res = await sdk.capabilities.list();
  expect(res.success, JSON.stringify(res.error)).toBeTruthy();
  return new Map((res.data?.capabilities ?? []).map((c) => [c.op, c]));
}

/**
 * Asserts control carries the Gated attributes for op as listed: a control
 * the server does not enable is disabled with the reason (or NOT_OFFERED) as
 * its title.
 */
async function expectGated(control: Locator, op: string, listed: Capabilities): Promise<void> {
  const cap = listed.get(op);
  const enabled = cap?.enabled === true;
  await expect(control).toHaveAttribute('data-capability-op', op);
  await expect(control).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
  if (!enabled) {
    await expect(control).toBeDisabled();
    await expect(control).toHaveAttribute('title', cap?.reason ?? NOT_OFFERED);
  }
}

const UNAVAILABLE = 'Compute is not available on this node';

// The SDK retries a 5xx refusal with backoff (1 s, 2 s, 4 s) before the page
// sees it.
const AFTER_RETRIES = { timeout: 20_000 };

/** Whether res is the structured 503 for a node without compute. */
async function notConfigured(res: Response): Promise<boolean> {
  if (res.status() !== 503) return false;
  const body = (await res.json().catch(() => undefined)) as { reason?: unknown } | undefined;
  return body?.reason === 'SERVICE_NOT_CONFIGURED';
}

test.describe('Compute pages', () => {
  test('the VM list shows what GET /api/v1/compute/vms answered', async ({ adminPage, sdk }) => {
    const listed = await capabilityMap(sdk);
    const vmsRes = apiResponse(adminPage, '/api/v1/compute/vms');
    await adminPage.goto('/compute/vms');
    const res = await vmsRes;

    if (res.status() === 503) {
      await expect(adminPage.getByText(UNAVAILABLE)).toBeVisible();
      await expect(adminPage.getByTestId('vm-table')).toHaveCount(0);
      return;
    }
    expect(res.ok(), `${res.url()} answered ${res.status()}`).toBeTruthy();
    const { vms = [] } = unwrapPayload<{ vms?: WireVM[] }>(await res.json());
    await expect(adminPage.getByTestId('vm-table')).toBeVisible();
    if (vms.length === 0) {
      await expect(adminPage.getByTestId('vm-table-empty')).toBeVisible();
    }
    await expect(adminPage.getByTestId('vm-row')).toHaveCount(vms.length);
    for (const vm of vms) {
      await expect(adminPage.getByTestId(`vm-link-${vm.id}`)).toBeVisible();
    }
    await expectGated(
      adminPage.getByRole('button', { name: 'Create VM' }),
      'POST /api/v1/compute/vms',
      listed,
    );
  });

  test('the snapshots page shows what the server answered', async ({ adminPage, sdk }) => {
    const listed = await capabilityMap(sdk);
    const vmsRes = apiResponse(adminPage, '/api/v1/compute/vms');
    await adminPage.goto('/compute/snapshots');
    const res = await vmsRes;

    if (res.status() === 503) {
      await expect(adminPage.getByText(UNAVAILABLE)).toBeVisible();
      return;
    }
    if (!res.ok()) {
      await expect(adminPage.getByText('Error Loading Snapshots')).toBeVisible();
      return;
    }
    await expectGated(
      adminPage.getByRole('button', { name: 'Create Snapshot' }),
      'POST /api/v1/compute/vms/{id}/snapshots',
      listed,
    );
  });

  test("a snapshot detail gates Refresh and shows the server's answer", async ({ adminPage, sdk }) => {
    const listed = await capabilityMap(sdk);
    const snapRes = apiResponse(adminPage, '/api/v1/compute/vms/vm-absent/snapshots/snap-absent');
    await adminPage.goto('/compute/snapshots/snap-absent?vm=vm-absent');
    const res = await snapRes;

    await expectGated(
      adminPage.getByRole('button', { name: 'Refresh' }),
      'GET /api/v1/compute/vms/{id}/snapshots/{snapshotId}',
      listed,
    );
    if (res.ok()) {
      // An answer without a snapshot is not found (setNotFound(!found)).
      const { snapshot } = unwrapPayload<{ snapshot?: unknown }>(await res.json());
      if (!snapshot) await expect(adminPage.getByText('Snapshot not found')).toBeVisible();
      return;
    }
    if (await notConfigured(res)) {
      // No compute on this node: the unavailable state, not an error toast.
      await expect(adminPage.getByText(UNAVAILABLE)).toBeVisible(AFTER_RETRIES);
      await expect(adminPage.getByText('Error loading snapshot')).toHaveCount(0);
      return;
    }
    // snapshot-detail-client.tsx toasts every other refused answer, and shows
    // "Snapshot not found" when the refusal is a 404.
    await expect(adminPage.getByText('Error loading snapshot').first()).toBeVisible();
    if (res.status() === 404) {
      await expect(adminPage.getByText('Snapshot not found')).toBeVisible();
    }
  });

  test('a VM detail shows what GET /api/v1/compute/vms/{id} answered', async ({ adminPage, sdk }) => {
    const list = await sdk.compute.listVMs();
    const first = list.success ? (list.data as { vms?: WireVM[] } | undefined)?.vms?.[0] : undefined;
    const id = first?.id ?? 'vm-absent';

    const vmRes = apiResponse(adminPage, `/api/v1/compute/vms/${encodeURIComponent(id)}`);
    await adminPage.goto(`/compute/vms/${encodeURIComponent(id)}`);
    const res = await vmRes;

    if (res.ok()) {
      const { vm } = unwrapPayload<{ vm?: WireVM }>(await res.json());
      await expect(adminPage.getByText('Virtual Machine Details')).toBeVisible();
      if (vm?.name) {
        await expect(adminPage.getByRole('heading', { level: 1 })).toHaveText(vm.name);
      }
      return;
    }
    if (await notConfigured(res)) {
      // No compute on this node: the unavailable state, not the error alert.
      await expect(adminPage.getByText(UNAVAILABLE)).toBeVisible(AFTER_RETRIES);
      await expect(adminPage.getByTestId('vm-detail-error')).toHaveCount(0);
      return;
    }
    // The SDK retries a 5xx refusal 1 s, 2 s, 4 s before the page shows its error state.
    await expect(adminPage.getByTestId('vm-detail-error')).toBeVisible(AFTER_RETRIES);
    await expect(adminPage.getByText('Virtual Machine Details')).toHaveCount(0);
  });
});
