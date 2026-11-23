/**
 * Real-server spec for the tenant quotas page, /tenant/quotas (#2067, UI epic
 * #1665): UpdateQuotas through Edit limits and CheckQuota through the Check
 * quota card. It runs against the real-server harness: no page.route mocks.
 * Every expectation is checked against what the server answered. The limits
 * the spec changes are put back in a finally block, and that answer is
 * checked too.
 */
import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

const UPDATE_OP = 'PUT /api/v1/tenants/{id}/quotas';
const CHECK_OP = 'POST /api/v1/tenants/{id}/quota-check';

const QUOTAS_PATH = /^\/api\/v1\/tenants\/[^/]+\/quotas$/;
const CHECK_PATH = /^\/api\/v1\/tenants\/[^/]+\/quota-check$/;

interface Capability {
  op: string;
  enabled: boolean;
  reason?: string;
}

interface QuotaLimits {
  compute?: { maxVms?: number; maxContainers?: number; maxVcpus?: number; maxMemoryMb?: number };
  network?: { maxBridges?: number; maxPorts?: number; maxBandwidthMbps?: number };
  storage?: { maxVolumesGb?: number; maxSnapshots?: number };
}

interface QuotaCheckAnswer {
  available?: boolean;
  message?: string;
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

function waitForApi(page: Page, method: string, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && path.test(new URL(r.url()).pathname),
  );
}

function limitsOf(body: unknown): QuotaLimits {
  const payload = unwrapPayload<QuotaLimits & { quotas?: QuotaLimits }>(body);
  const limits = payload.quotas ?? payload;
  return { compute: limits.compute, network: limits.network, storage: limits.storage };
}

/** Opens the quotas page and returns the limits and path of the page's own GET. */
async function openQuotas(page: Page): Promise<{ limits: QuotaLimits; path: string }> {
  const read = waitForApi(page, 'GET', QUOTAS_PATH);
  await page.goto('/tenant/quotas');
  const res = await read;
  expect(res.ok()).toBeTruthy();
  await expect(page.getByText('Quota Limits Reference')).toBeVisible();
  return { limits: limitsOf(await res.json()), path: new URL(res.url()).pathname };
}

async function withheld(page: Page, name: string, cap: Capability): Promise<void> {
  const button = page.getByRole('button', { name, exact: true });
  await expect(button).toHaveAttribute('data-capability-op', cap.op);
  await expect(button).toHaveAttribute('data-capability-enabled', 'false');
  await expect(button).toBeDisabled();
  if (cap.reason) {
    await expect(button).toHaveAttribute('title', cap.reason);
  }
}

test.describe('Tenant quotas (real server)', () => {
  test.describe.configure({ mode: 'serial' });

  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/tenant/quotas');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('Edit limits sets Max VMs and the server reads it back', async ({ adminPage, sdk }) => {
    const cap = capabilityOf(await listCapabilities(sdk), UPDATE_OP);
    const { limits: original, path } = await openQuotas(adminPage);

    if (!cap.enabled) {
      await withheld(adminPage, 'Edit limits', cap);
      test.skip(true, cap.reason ?? 'the server does not enable PUT /api/v1/tenants/{id}/quotas');
      return;
    }

    const wanted = (original.compute?.maxVms ?? 0) + 1;
    try {
      await adminPage.getByRole('button', { name: 'Edit limits', exact: true }).click();
      await adminPage.getByLabel('Max VMs').fill(String(wanted));
      const put = waitForApi(adminPage, 'PUT', QUOTAS_PATH);
      await adminPage.getByRole('button', { name: 'Save limits', exact: true }).click();
      const putRes = await put;
      expect(putRes.ok()).toBeTruthy();

      const readBack = await adminPage.request.get(path);
      expect(readBack.ok()).toBeTruthy();
      expect(limitsOf(await readBack.json()).compute?.maxVms).toBe(wanted);
    } finally {
      const restore = await adminPage.request.put(path, { data: original });
      expect(restore.ok()).toBeTruthy();
    }
  });

  test('Check quota shows what the server answered for one VM', async ({ adminPage, sdk }) => {
    const cap = capabilityOf(await listCapabilities(sdk), CHECK_OP);
    await openQuotas(adminPage);

    if (!cap.enabled) {
      await withheld(adminPage, 'Check quota', cap);
      test.skip(true, cap.reason ?? 'the server does not enable POST /api/v1/tenants/{id}/quota-check');
      return;
    }

    await adminPage.getByLabel('Resource').selectOption('vms');
    await adminPage.getByLabel('Amount').fill('1');
    const post = waitForApi(adminPage, 'POST', CHECK_PATH);
    await adminPage.getByRole('button', { name: 'Check quota', exact: true }).click();
    const res = await post;
    expect(res.request().postDataJSON()).toEqual({ resource: 'vms', amount: 1 });

    const result = adminPage.getByTestId('tenant-quota-check-result');
    const body = await res.json();
    if (!res.ok()) {
      const message = (body as { error?: { message?: string }; message?: string }).error?.message
        ?? (body as { message?: string }).message;
      await expect(result).not.toHaveText('');
      if (message) {
        await expect(result).toContainText(message);
      }
      return;
    }
    const answer = unwrapPayload<QuotaCheckAnswer>(body);
    if (answer.available) {
      await expect(result).toContainText('Available');
    } else {
      await expect(result).toContainText(answer.message || 'Not available');
    }
  });
});
