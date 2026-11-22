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
    // pass (#2179 Codex). A node without a perf backend answers with a refusal
    // the server writes as its JSON error envelope (no bridge: 404; no gateway
    // server: 503; 409 or 500 from the backend), and the page must show it; a
    // missing route, a wrong method or a non-JSON answer fails. A 200 must
    // show the benchmark result.
    expect([401, 403]).not.toContain(res.status());
    const result = authenticatedPage.getByTestId('perf-flows-result');
    const error = authenticatedPage.getByTestId('perf-flows-error');
    if (res.ok()) {
      expect(res.status()).toBe(200);
      await expect(result).toBeVisible();
      await expect(error).toHaveCount(0);
    } else {
      // A 404 counts only with the server's JSON envelope: the perf service
      // answers a missing bridge as NotFound, an unregistered route answers
      // plain text.
      const body: unknown = await res.json().catch(() => null);
      expect(body, 'refusal is the server JSON envelope, not a missing route').not.toBeNull();
      expect(typeof body).toBe('object');
      const envelope = body as { error?: unknown; message?: unknown };
      const message =
        typeof envelope.error === 'string' && envelope.error !== '' ? envelope.error : envelope.message;
      expect(typeof message, 'refusal carries the server error text').toBe('string');
      expect(message).not.toBe('');
      expect(res.status()).not.toBe(405);
      expect([404, 409, 500, 503]).toContain(res.status());
      await expect(authenticatedPage.getByText('Benchmark not run')).toBeVisible();
      await expect(error).toBeVisible();
      await expect(result).toHaveCount(0);
      await expect(error).toContainText(message as string);
    }
    await expect(authenticatedPage.getByTestId('perf-flows-run')).toBeEnabled();

    // One confirmation is one run: the SDK never re-sends the POST (#2179
    // Codex).
    await authenticatedPage.waitForLoadState('networkidle');
    expect(posts).toHaveLength(1);
  });
});
