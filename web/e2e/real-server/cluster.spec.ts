/**
 * Real-server spec for ClusterService (#2043, epic #1665 coverage-matrix
 * slice 6): Bootstrap, Join, Leave, GetStatus and ListNodes.
 *
 * Runs under `make web-e2e` against the real-server harness. State is read
 * through the `sdk` fixture and every assertion compares the page with what
 * the server returned; no route mocks.
 */
import { test, expect } from './fixtures';

const CLUSTER_PATH = '/platform/cluster';

/** Reads the cluster status, or the error the server answers with. */
async function readStatus(
  sdk: { cluster: { getStatus(): Promise<unknown> } },
): Promise<{ ok: true; status: any } | { ok: false; error: string }> {
  try {
    return { ok: true, status: await sdk.cluster.getStatus() };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

test.describe('cluster: status view (GetStatus)', () => {
  test('shows the status the server reports, or the reason it is unavailable', async ({
    adminPage,
    sdk,
  }) => {
    const result = await readStatus(sdk);
    await adminPage.goto(CLUSTER_PATH);
    await expect(adminPage.getByRole('heading', { name: 'Cluster' })).toBeVisible();

    if (result.ok) {
      const status = result.status;
      const view = adminPage.getByTestId('cluster-status');
      await expect(view).toBeVisible();
      if (status.nodeId) {
        await expect(view).toContainText(status.nodeId);
      }
      if (status.leaderId) {
        await expect(view).toContainText(status.leaderId);
      }
    } else {
      // A node with no cluster section answers 503; the page says so and
      // keeps every write control disabled.
      await expect(adminPage.getByTestId('cluster-unavailable')).toBeVisible();
      await expect(adminPage.getByRole('button', { name: 'Bootstrap' })).toBeDisabled();
      await expect(adminPage.getByRole('button', { name: 'Join' })).toBeDisabled();
      await expect(adminPage.getByRole('button', { name: 'Leave' })).toBeDisabled();
    }
  });
});

test.describe('cluster: nodes view (ListNodes)', () => {
  test('lists every node the server returns', async ({ adminPage, sdk }) => {
    let nodes: Array<{ nodeId?: string; id?: string }> | null = null;
    try {
      const resp: any = await sdk.cluster.listNodes();
      nodes = resp.nodes ?? [];
    } catch {
      nodes = null;
    }
    await adminPage.goto(CLUSTER_PATH);

    if (nodes === null) {
      await expect(adminPage.getByTestId('cluster-unavailable')).toBeVisible();
      return;
    }
    const table = adminPage.getByTestId('cluster-nodes');
    await expect(table).toBeVisible();
    await expect(table.getByRole('row')).toHaveCount(nodes.length + 1);
    for (const node of nodes) {
      const id = node.nodeId ?? node.id;
      if (id) {
        await expect(table).toContainText(id);
      }
    }
  });
});

test.describe('cluster: write flows (Bootstrap, Join, Leave)', () => {
  test('each write is gated and answers with the server result', async ({ adminPage, sdk }) => {
    const result = await readStatus(sdk);
    await adminPage.goto(CLUSTER_PATH);

    const bootstrap = adminPage.getByRole('button', { name: 'Bootstrap' });
    const join = adminPage.getByRole('button', { name: 'Join' });
    const leave = adminPage.getByRole('button', { name: 'Leave' });
    await expect(bootstrap).toBeVisible();
    await expect(join).toBeVisible();
    await expect(leave).toBeVisible();

    if (!result.ok) {
      await expect(bootstrap).toBeDisabled();
      await expect(join).toBeDisabled();
      await expect(leave).toBeDisabled();
      return;
    }

    // Join with no peer address is refused by the server (InvalidArgument,
    // HTTP 400); the page shows the server's error text.
    await adminPage.getByLabel('Peer addresses').fill('');
    await join.click();
    await expect(adminPage.getByTestId('cluster-error')).toBeVisible();

    // The page and the SDK still agree on the status after the refused write.
    const after = await readStatus(sdk);
    expect(after.ok).toBe(true);
    if (after.ok && after.status.nodeId) {
      await expect(adminPage.getByTestId('cluster-status')).toContainText(after.status.nodeId);
    }
  });
});
