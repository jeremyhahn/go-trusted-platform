import type { Request } from '@playwright/test';
import { test, expect } from './fixtures/auth.fixture';

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
  test('cancel installs nothing', async ({ authenticatedPage }) => {
    const posts: Request[] = [];
    authenticatedPage.on('request', (r) => {
      if (isPerfFlowsPost(r)) posts.push(r);
    });

    await authenticatedPage.goto('/networking/gateway');
    await authenticatedPage.getByTestId('perf-flows-run').click();

    const dialog = authenticatedPage.getByTestId('perf-flows-dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText('Install temporary switch flows?');
    await expect(dialog).toContainText('expire when the run ends');

    await authenticatedPage.getByTestId('perf-flows-cancel').click();
    await expect(dialog).toBeHidden();
    await authenticatedPage.waitForLoadState('networkidle');
    expect(posts).toHaveLength(0);
  });

  test('confirm runs one benchmark and the page answers', async ({ authenticatedPage }) => {
    await authenticatedPage.goto('/networking/gateway');
    await authenticatedPage.getByTestId('perf-flows-run').click();
    await expect(authenticatedPage.getByTestId('perf-flows-dialog')).toBeVisible();

    const req = authenticatedPage.waitForRequest(isPerfFlowsPost);
    await authenticatedPage.getByTestId('perf-flows-confirm').click();
    const sent = await req;
    expect(sent.postDataJSON()).toEqual({ count: 1000, batch: true });

    // A node without a perf backend answers with a refusal; either way the
    // round trip reached the server and the page shows its answer.
    await expect(
      authenticatedPage.getByTestId('perf-flows-result').or(authenticatedPage.getByTestId('perf-flows-error'))
    ).toBeVisible();
    await expect(authenticatedPage.getByTestId('perf-flows-run')).toBeEnabled();
  });
});
