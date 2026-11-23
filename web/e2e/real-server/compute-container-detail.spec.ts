/**
 * Container detail page against the real server (#2045, epic #1665).
 *
 * The test daemon has no compute section, so the server answers a compute
 * read with the structured not-configured 503 and lists the compute ops
 * disabled. The page must show the not-configured state for it; on a node
 * with compute, a refused load of a missing container shows the server's
 * reason. Read-only: no request is routed, nothing is written and no control
 * is clicked.
 */
import type { Page, Response } from '@playwright/test';
import { isServiceNotConfigured } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

// The SDK retries a 5xx after 1 s, 2 s and 4 s before the page settles.
const AFTER_RETRIES = { timeout: 20_000 };

const MISSING = 'e2e-missing-container';

// Every op the row gates or reads, verbatim from the server's route table.
const ROW_OPS = [
  'GET /api/v1/compute/containers/{id}',
  'GET /api/v1/compute/containers/{id}/metrics',
  'POST /api/v1/compute/containers/{id}/exec',
  'POST /api/v1/compute/containers/{id}/attest',
  'POST /api/v1/compute/vms/{id}/attest',
  'POST /api/v1/compute/vms/{id}/attest/verify',
];

/** Waits for the page's own GET of exactly this path. */
function pageGet(page: Page, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path,
  );
}

test.describe('Container detail page', () => {
  test('a refused container load shows compute not available or the server reason', async ({
    adminPage,
  }) => {
    const answer = pageGet(adminPage, `/api/v1/compute/containers/${MISSING}`);
    await adminPage.goto(`/compute/containers/${MISSING}`);
    const res = await answer;
    expect(res.ok()).toBe(false);

    const body = (await res.json()) as { error?: unknown; reason?: unknown };
    expect(() => unwrapPayload(body)).toThrow(/error envelope/);

    // Next.js's route announcer is a role alert too: look only at the
    // page's load error.
    const loadError = adminPage.getByRole('alert').filter({ hasText: 'Failed to load container' });
    if (body.reason === 'SERVICE_NOT_CONFIGURED') {
      await expect(adminPage.getByText('Compute is not available on this node')).toBeVisible(
        AFTER_RETRIES,
      );
      await expect(loadError).toHaveCount(0);
    } else {
      const alert = loadError;
      await expect(alert).toBeVisible(AFTER_RETRIES);
      await expect(alert).toContainText('Failed to load container');
      expect(typeof body.error).toBe('string');
      await expect(alert).toContainText(String(body.error));
    }
    await expect(adminPage.getByText('Container Details')).toHaveCount(0);
  });

  test('the server lists every op the row gates or reads', async ({ sdk }) => {
    const list = await sdk.capabilities.list();
    expect(list.success, JSON.stringify(list.error)).toBe(true);
    const caps = new Map((list.data?.capabilities ?? []).map((c) => [c.op, c]));

    for (const op of ROW_OPS) {
      expect(caps.has(op), `capabilities list carries ${op}`).toBe(true);
    }

    const res = await sdk.compute.getContainer(MISSING);
    if (res.success === false && isServiceNotConfigured(res.error)) {
      for (const op of ROW_OPS) {
        const cap = caps.get(op);
        expect(cap?.enabled, `${op} is disabled without compute`).toBe(false);
        expect(cap?.reason ?? '', `${op} names why`).toMatch(/^not-configured: /);
      }
    }
  });
});
