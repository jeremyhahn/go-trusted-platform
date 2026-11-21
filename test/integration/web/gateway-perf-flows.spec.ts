import type { Request } from '@playwright/test';
import { test, expect } from './fixtures/admin-session.fixture';

/**
 * Gateway flow-programming benchmark (#2052, ruling 972).
 *
 * GetPerfFlows installs temporary switch flows, so the gateway page offers it
 * as one admin-only action behind a confirm dialog. Against the real server
 * (no api-mock): cancel sends nothing; confirm sends exactly one POST and the
 * page answers with the result or the server's refusal, and can run again.
 */

const PERF_FLOWS_PATH = '/api/v1/gateway/perf/flows';

function isPerfFlowsPost(r: Request): boolean {
  return r.url().includes(PERF_FLOWS_PATH) && r.method() === 'POST';
}

test.describe('Gateway flow benchmark', () => {
  test('cancel installs nothing', async ({ adminPage: authenticatedPage }) => {
    const posts: Request[] = [];
    authenticatedPage.on('request', (r) => {
      if (isPerfFlowsPost(r)) posts.push(r);
    });

    await authenticatedPage.goto('/networking/gateway');
    await authenticatedPage.getByTestId('perf-flows-run').click();

    const dialog = authenticatedPage.getByTestId('perf-flows-dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText('Install temporary switch flows?');
    await expect(dialog).toContainText('deletes them when the run ends');

    await authenticatedPage.getByTestId('perf-flows-cancel').click();
    await expect(dialog).toBeHidden();
    await authenticatedPage.waitForLoadState('networkidle');
    expect(posts).toHaveLength(0);
  });

  test('confirm runs one benchmark and the page answers', async ({ adminPage: authenticatedPage }) => {
    const posts: Request[] = [];
    authenticatedPage.on('request', (r) => {
      if (isPerfFlowsPost(r)) posts.push(r);
    });

    await authenticatedPage.goto('/networking/gateway');
    await authenticatedPage.getByTestId('perf-flows-run').click();
    await expect(authenticatedPage.getByTestId('perf-flows-dialog')).toBeVisible();

    const req = authenticatedPage.waitForRequest(isPerfFlowsPost);
    const answer = authenticatedPage.waitForResponse((r) => isPerfFlowsPost(r.request()));
    await authenticatedPage.getByTestId('perf-flows-confirm').click();
    const sent = await req;
    expect(sent.postDataJSON()).toEqual({ count: 1000, batch: true });
    const res = await answer;

    // The session is server-issued, so an auth refusal is a failure, never a
    // pass (#2179 Codex). A node without a perf backend (no gateway server:
    // 503; no OVS: an error status) answers with a refusal, and the page must
    // show that refusal; a 200 must show the benchmark result.
    expect([401, 403]).not.toContain(res.status());
    const result = authenticatedPage.getByTestId('perf-flows-result');
    const error = authenticatedPage.getByTestId('perf-flows-error');
    if (res.ok()) {
      expect(res.status()).toBe(200);
      await expect(result).toBeVisible();
      await expect(error).toHaveCount(0);
    } else {
      expect(res.status() === 503 || res.status() >= 400).toBe(true);
      await expect(authenticatedPage.getByText('Benchmark not run')).toBeVisible();
      await expect(error).toBeVisible();
      await expect(result).toHaveCount(0);
      const body: unknown = await res.json().catch(() => null);
      const message =
        body !== null && typeof body === 'object'
          ? ((body as { message?: unknown }).message ?? (body as { error?: unknown }).error)
          : undefined;
      if (typeof message === 'string' && message !== '') {
        await expect(error).toContainText(message);
      }
    }
    await expect(authenticatedPage.getByTestId('perf-flows-run')).toBeEnabled();

    // One confirmation is one run: the SDK never re-sends the POST (#2179
    // Codex).
    await authenticatedPage.waitForLoadState('networkidle');
    expect(posts).toHaveLength(1);
  });
});
