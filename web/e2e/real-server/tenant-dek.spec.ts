/**
 * Real-server spec for the tenant DEK card on /tenant/barrier (#2067, UI
 * epic #1665). It runs against the real-server harness: no page.route mocks.
 * Every expectation is checked against what the server answered: the DEK
 * status read and the capabilities listing. The spec never rotates the
 * fixture tenant's DEK: it opens the confirm and cancels it.
 */
import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

const STATUS_OP = 'GET /api/v1/tenants/{id}/dek';
const ROTATE_OP = 'POST /api/v1/tenants/{id}/dek/rotate';

interface Capability {
  op: string;
  enabled: boolean;
  reason?: string;
}

interface DEKStatus {
  tenantId?: string;
  version?: number;
  algorithm?: string;
  status?: string;
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

function dekPath(tenantId: string, suffix = ''): string {
  return `/api/v1/tenants/${tenantId}/dek${suffix}`;
}

function dekResponse(page: Page, method: string, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && new URL(r.url()).pathname === path,
  );
}

test.describe('Tenant DEK (real server)', () => {
  test.describe.configure({ mode: 'serial' });

  test('shows the DEK status the server answers, or the listed reason', async ({ adminPage, sdk, tenant }) => {
    const capabilities = await listCapabilities(sdk);
    const statusCap = capabilityOf(capabilities as Capability[], STATUS_OP);
    const card = adminPage.getByTestId('tenant-dek-status');

    if (!statusCap.enabled) {
      const reads: string[] = [];
      adminPage.on('request', (r) => {
        if (r.method() === 'GET' && new URL(r.url()).pathname === dekPath(tenant.id)) {
          reads.push(r.url());
        }
      });
      await adminPage.goto('/tenant/barrier');
      // The server lists a disabled op with its reason, e.g.
      // `not-configured: tenant-dek` when no DEK backend is wired.
      expect(statusCap.reason).toBeTruthy();
      await expect(adminPage.getByText(statusCap.reason ?? '', { exact: true })).toBeVisible();
      await expect(card).toHaveCount(0);
      expect(reads).toEqual([]);
      return;
    }

    const statusRes = dekResponse(adminPage, 'GET', dekPath(tenant.id));
    await adminPage.goto('/tenant/barrier');
    const res = await statusRes;
    expect(res.ok()).toBeTruthy();
    const { dekStatus } = unwrapPayload<{ dekStatus?: DEKStatus }>(await res.json());
    expect(dekStatus).toBeDefined();
    await expect(card).toContainText(`version ${dekStatus?.version}`);
    if (dekStatus?.algorithm) {
      await expect(card).toContainText(dekStatus.algorithm);
    }
  });

  test('gates Rotate DEK as the server lists it and never rotates the fixture DEK', async ({ adminPage, sdk, tenant }) => {
    const capabilities = await listCapabilities(sdk);
    const cap = capabilityOf(capabilities as Capability[], ROTATE_OP);
    const rotates: string[] = [];
    adminPage.on('request', (r) => {
      if (r.method() === 'POST' && new URL(r.url()).pathname === dekPath(tenant.id, '/rotate')) {
        rotates.push(r.url());
      }
    });

    await adminPage.goto('/tenant/barrier');
    const button = adminPage.getByRole('button', { name: 'Rotate DEK', exact: true });
    await expect(button).toHaveAttribute('data-capability-op', ROTATE_OP);
    await expect(button).toHaveAttribute('data-capability-enabled', cap.enabled ? 'true' : 'false');

    if (!cap.enabled) {
      await expect(button).toBeDisabled();
      if (cap.reason) {
        await expect(button).toHaveAttribute('title', cap.reason);
      }
    } else {
      await button.click();
      const dialog = adminPage.getByRole('dialog');
      await expect(dialog.getByText('Rotate the tenant DEK?')).toBeVisible();
      await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
      await expect(dialog).toHaveCount(0);
    }
    expect(rotates).toEqual([]);
  });
});
