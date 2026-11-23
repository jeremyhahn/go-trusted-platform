import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The cluster page against the real platformd (#2043, epic #1665). No
 * page.route mocks and no writes: the test daemon config seeds no cluster
 * section, so each assertion compares the page with what the server answered
 * the page itself (503 not configured, or a status and a node list), not with
 * a fixed state.
 */

/** The reason the capability gate shows for an op the server does not list. */
const NOT_OFFERED = 'not offered by this server';

/** Waits for the page's own GET on exactly this path. */
function apiResponse(page: Page, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path,
  );
}

test.describe('Cluster page', () => {
  test('the cluster page shows what the server answers for its status and nodes', async ({
    adminPage,
  }) => {
    const statusRes = apiResponse(adminPage, '/api/v1/cluster/status');
    const nodesRes = apiResponse(adminPage, '/api/v1/cluster/nodes');
    await adminPage.goto('/platform/cluster');
    const status = await statusRes;
    const nodes = await nodesRes;

    if (status.status() === 503) {
      await expect(adminPage.getByTestId('cluster-not-configured')).toBeVisible();
      await expect(adminPage.getByTestId('cluster-status')).toHaveCount(0);
      await expect(adminPage.getByTestId('cluster-nodes')).toHaveCount(0);
      await expect(adminPage.getByTestId('cluster-membership')).toHaveCount(0);
      return;
    }

    if (!status.ok()) {
      // Any other refused status read shows the server's message in an alert.
      await expect(adminPage.getByRole('alert').first()).toBeVisible();
      await expect(adminPage.getByTestId('cluster-status')).toHaveCount(0);
      return;
    }

    await expect(adminPage.getByTestId('cluster-status')).toBeVisible();
    if (nodes.ok()) {
      const body = unwrapPayload<{ nodes?: Array<{ id: string }> }>(await nodes.json());
      const listed = body.nodes ?? [];
      const rows = adminPage.getByTestId('cluster-nodes').locator('tbody tr');
      await expect(rows).toHaveCount(listed.length);
      for (const node of listed) {
        await expect(rows.filter({ hasText: node.id })).toHaveCount(1);
      }
    } else {
      await expect(adminPage.getByRole('alert').first()).toBeVisible();
      await expect(adminPage.getByTestId('cluster-nodes')).toHaveCount(0);
    }
  });

  test("the membership card gates Bootstrap, Join and Leave on the server's capabilities", async ({
    adminPage,
    sdk,
  }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map((res.data?.capabilities ?? []).map((c) => [c.op, c]));

    const statusRes = apiResponse(adminPage, '/api/v1/cluster/status');
    await adminPage.goto('/platform/cluster');
    const status = await statusRes;
    if (status.status() === 503) {
      // Not configured: the page offers no membership controls at all.
      await expect(adminPage.getByTestId('cluster-not-configured')).toBeVisible();
      await expect(adminPage.getByTestId('cluster-membership')).toHaveCount(0);
      return;
    }

    const card = adminPage.getByTestId('cluster-membership');
    await expect(card).toBeVisible();
    for (const [name, op] of [
      ['Bootstrap', 'POST /api/v1/cluster/bootstrap'],
      ['Join', 'POST /api/v1/cluster/join'],
      ['Leave', 'POST /api/v1/cluster/leave'],
    ] as const) {
      const button = card.getByRole('button', { name, exact: true });
      const cap = listed.get(op);
      const enabled = cap?.enabled === true;
      await expect(button).toHaveAttribute('data-capability-op', op);
      await expect(button).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
      if (!enabled) {
        await expect(button).toBeDisabled();
        await expect(button).toHaveAttribute('title', cap ? (cap.reason ?? '') : NOT_OFFERED);
      }
    }
  });
});
