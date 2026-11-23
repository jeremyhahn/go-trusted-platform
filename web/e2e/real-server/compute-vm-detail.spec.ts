import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { isServiceNotConfigured } from 'trusted-platform-sdk';
import { unwrapPayload } from './fixtures/wire';

/**
 * The VM detail page against the real platformd (#2044, epic #1665).
 *
 * The test daemon's config (web/e2e/real-server/platformd.test.yaml) has no
 * compute section, so the server refuses the VM load with the structured 503
 * reason SERVICE_NOT_CONFIGURED and the page shows "Compute is not available
 * on this node"; a server with compute configured refuses an unknown VM id
 * instead and the page shows its error state with the server's reason. Never
 * an endless spinner. The ops the page's controls gate are checked against
 * GET /api/v1/capabilities.
 *
 * Read-only: no page.route, no writes, and no write control is clicked.
 */

// The SDK retries a 5xx refusal with backoff (1 s, 2 s, 4 s) before the page
// sees it.
const AFTER_RETRIES = { timeout: 20_000 };

/** Waits for the page's own GET of exactly path. */
function apiResponse(page: Page, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path,
  );
}

const MISSING_VM = 'e2e-missing-vm';

const UNAVAILABLE = 'Compute is not available on this node';

// Every op a control on the VM detail page (and its cards) gates.
const DETAIL_OPS = [
  'POST /api/v1/compute/vms/{id}/start',
  'POST /api/v1/compute/vms/{id}/stop',
  'POST /api/v1/compute/vms/{id}/suspend',
  'POST /api/v1/compute/vms/{id}/reboot',
  'POST /api/v1/compute/vms/{id}/resume',
  'DELETE /api/v1/compute/vms/{id}',
  'POST /api/v1/compute/vms/{id}/migrate',
  'POST /api/v1/compute/vms/{id}/attest',
  'GET /api/v1/compute/vms/{id}/metrics',
  'POST /api/v1/compute/vms/{id}/disks',
  'PATCH /api/v1/compute/vms/{id}/disks/{diskId}',
  'DELETE /api/v1/compute/vms/{id}/disks/{diskId}',
] as const;

test.describe('VM detail page', () => {
  test('a refused VM load shows the error state with the server reason', async ({ adminPage }) => {
    const vmRes = apiResponse(adminPage, `/api/v1/compute/vms/${MISSING_VM}`);
    await adminPage.goto(`/compute/vms/${MISSING_VM}`);
    const res = await vmRes;

    expect(res.ok(), `${res.url()} answered ${res.status()} for an unknown VM`).toBeFalsy();
    const body: unknown = await res.json();
    // An error envelope carries no payload: unwrapPayload refuses it with the reason.
    expect(() => unwrapPayload(body)).toThrow(/error envelope/);
    const envelope = body as { error?: unknown; reason?: unknown };
    const reason = envelope.error;

    const error = adminPage.getByTestId('vm-detail-error');
    if (envelope.reason === 'SERVICE_NOT_CONFIGURED') {
      // No compute on this node: the page says so instead of an error alert.
      await expect(adminPage.getByText(UNAVAILABLE)).toBeVisible(AFTER_RETRIES);
      await expect(error).toHaveCount(0);
      return;
    }
    await expect(error).toBeVisible(AFTER_RETRIES);
    if (typeof reason === 'string' && reason !== '') {
      await expect(error).toContainText(reason);
    }
    await expect(adminPage.getByText('Virtual Machine Details')).toHaveCount(0);
  });

  test('the server lists every op the VM detail page gates', async ({ sdk }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map((res.data?.capabilities ?? []).map((c) => [c.op, c]));

    // Without compute the server still lists each op, disabled with a
    // not-configured reason, so no control reads "not offered".
    const vm = await sdk.compute.getVM(MISSING_VM);
    const notConfigured = vm.success === false && isServiceNotConfigured(vm.error);

    for (const op of DETAIL_OPS) {
      const cap = listed.get(op);
      expect(cap, `the capability list carries ${op}`).toBeDefined();
      if (notConfigured) {
        expect(cap?.enabled, `${op} is off without compute`).toBe(false);
        expect(cap?.reason ?? '').toMatch(/^not-configured: /);
      }
    }
  });
});
