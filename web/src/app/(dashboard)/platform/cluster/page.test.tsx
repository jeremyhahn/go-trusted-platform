import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';

import ClusterPage from './page';

const STATUS = '/api/v1/cluster/status';
const NODES = '/api/v1/cluster/nodes';

const statusOK: Answer = {
  status: 200,
  body: {
    cluster: { id: 'c1', name: 'lab', state: 2, leader_id: 'n1', total_nodes: 2, healthy_nodes: 1, term: 7 },
  },
};

const noNodes: Answer = { status: 200, body: { nodes: [], total: 0 } };

function statusReads(sent: { path: string }[]): number {
  return sent.filter((r) => r.path === STATUS).length;
}

describe('ClusterPage', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the cluster status and its nodes', async () => {
    stubControlPlane({
      [`GET ${STATUS}`]: statusOK,
      [`GET ${NODES}`]: {
        status: 200,
        body: {
          nodes: [
            { id: 'n1', name: 'alpha', address: '10.0.0.1', port: 7946, role: 1, state: 2, version: 'v1' },
            { id: 'n2', name: 'beta', role: 2, state: 6 },
          ],
          total: 2,
        },
      },
    });
    render(withControlPlane(<ClusterPage />));

    expect(await screen.findByText('lab')).toBeTruthy();
    const card = within(screen.getByTestId('cluster-status'));
    expect(card.getByText('Healthy')).toBeTruthy();
    expect(card.getByText('1 / 2')).toBeTruthy();

    const table = within(await screen.findByTestId('cluster-nodes'));
    expect(await table.findByText('alpha')).toBeTruthy();
    expect(table.getByText('10.0.0.1:7946')).toBeTruthy();
    expect(table.getByText('Leader')).toBeTruthy();
    expect(table.getByText('Unreachable')).toBeTruthy();
  });

  it('shows Cluster not configured on a 503 and does not retry', async () => {
    const notConfigured: Answer = { status: 503, body: { error: 'cluster service not configured' } };
    const sent = stubControlPlane({ [`GET ${STATUS}`]: notConfigured, [`GET ${NODES}`]: notConfigured });
    render(withControlPlane(<ClusterPage />));

    expect(await screen.findByText('Cluster not configured')).toBeTruthy();
    expect(screen.getByText('cluster service not configured')).toBeTruthy();
    expect(screen.queryByTestId('cluster-nodes')).toBeNull();
    expect(statusReads(sent)).toBe(1);
  });

  it('shows a refused read', async () => {
    stubControlPlane({
      [`GET ${STATUS}`]: { status: 403, body: { error: 'cluster read denied' } },
      [`GET ${NODES}`]: noNodes,
    });
    render(withControlPlane(<ClusterPage />));

    expect(await screen.findByText('cluster read denied')).toBeTruthy();
    expect(screen.queryByText('Cluster not configured')).toBeNull();
  });

  it('Refresh re-reads the status', async () => {
    const sent = stubControlPlane({ [`GET ${STATUS}`]: statusOK, [`GET ${NODES}`]: noNodes });
    render(withControlPlane(<ClusterPage />));

    expect(await screen.findByText('lab')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: /Refresh/ }));
    await waitFor(() => expect(statusReads(sent)).toBe(2));
  });
});
