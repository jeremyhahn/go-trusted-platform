import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The VM detail page against the real platformd (#2044, epic #1665).
 *
 * The test daemon's config (web/e2e/real-server/platformd.test.yaml) has no
 * compute section, so the server refuses the VM load (503 not configured);
 * a server with compute configured refuses an unknown VM id instead. Either
 * way the page shows its error state with the server's reason, not an
 * endless spinner.
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

test.describe('VM detail page', () => {
  test('a refused VM load shows the error state with the server reason', async ({ adminPage }) => {
    const vmRes = apiResponse(adminPage, `/api/v1/compute/vms/${MISSING_VM}`);
    await adminPage.goto(`/compute/vms/${MISSING_VM}`);
    const res = await vmRes;

    expect(res.ok(), `${res.url()} answered ${res.status()} for an unknown VM`).toBeFalsy();
    const body: unknown = await res.json();
    // An error envelope carries no payload: unwrapPayload refuses it with the reason.
    expect(() => unwrapPayload(body)).toThrow(/error envelope/);
    const reason = (body as { error?: unknown }).error;

    const error = adminPage.getByTestId('vm-detail-error');
    await expect(error).toBeVisible(AFTER_RETRIES);
    if (typeof reason === 'string' && reason !== '') {
      await expect(error).toContainText(reason);
    }
    await expect(adminPage.getByText('Virtual Machine Details')).toHaveCount(0);
  });
});
