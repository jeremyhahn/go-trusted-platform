import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import {
  clusterStateLabel,
  nodeRoleLabel,
  nodeStateLabel,
  useCluster,
  type NodeState,
} from './use-cluster';

function renderCluster() {
  return renderHook(() => useCluster(), {
    wrapper: ({ children }) => withControlPlane(children),
  });
}

// The connection drops before any response arrives: the server may already
// have applied the write.
function stubLostResponse() {
  const fetchMock = vi.fn(async () => {
    throw new TypeError('fetch failed');
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

describe('useCluster', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads the status through GET /cluster/status', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/cluster/status': {
        status: 200,
        body: {
          cluster: { id: 'c1', name: 'lab', state: 2, leader_id: 'n1', total_nodes: 3, healthy_nodes: 3 },
          local_node: { id: 'n1', role: 1, state: 2 },
        },
      },
    });
    const { result } = renderCluster();
    let res: Awaited<ReturnType<typeof result.current.getStatus>> | undefined;
    await act(async () => {
      res = await result.current.getStatus();
    });
    expect(res?.success).toBe(true);
    expect(res?.data?.cluster?.total_nodes).toBe(3);
    expect(clusterStateLabel(res?.data?.cluster?.state)).toBe('Healthy');
    expect(sent).toEqual([{ method: 'GET', path: '/api/v1/cluster/status', body: undefined }]);
  });

  it('lists nodes through GET /cluster/nodes', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/cluster/nodes': {
        status: 200,
        body: {
          nodes: [
            { id: 'n1', role: 1, state: 2 },
            { id: 'n2', role: 2, state: 6 },
          ],
          total: 2,
        },
      },
    });
    const { result } = renderCluster();
    let res: Awaited<ReturnType<typeof result.current.listNodes>> | undefined;
    await act(async () => {
      res = await result.current.listNodes();
    });
    expect(res?.data?.nodes?.map((n) => n.id)).toEqual(['n1', 'n2']);
    expect(nodeRoleLabel(res?.data?.nodes?.[1]?.role)).toBe('Follower');
    expect(nodeStateLabel(res?.data?.nodes?.[1]?.state)).toBe('Unreachable');
    expect(sent).toEqual([{ method: 'GET', path: '/api/v1/cluster/nodes', body: undefined }]);
  });

  it('bootstraps with a snake_case body through POST /cluster/bootstrap', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/cluster/bootstrap': {
        status: 200,
        body: { status: { success: true }, cluster: { id: 'c1', state: 1 }, node: { id: 'n1' } },
      },
    });
    const { result } = renderCluster();
    let res: Awaited<ReturnType<typeof result.current.bootstrap>> | undefined;
    await act(async () => {
      res = await result.current.bootstrap({
        cluster_name: 'lab',
        node_name: 'n1',
      });
    });
    expect(sent[0]).toEqual({
      method: 'POST',
      path: '/api/v1/cluster/bootstrap',
      body: { cluster_name: 'lab', node_name: 'n1' },
    });
    expect(res?.data?.status?.success).toBe(true);
  });

  it('joins with its seed addresses through POST /cluster/join', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/cluster/join': {
        status: 200,
        body: { status: { success: true }, node: { id: 'n2' } },
      },
    });
    const { result } = renderCluster();
    await act(async () => {
      await result.current.join({ node_name: 'n2', seed_addresses: ['seed-a:7946'] });
    });
    expect(sent[0].method).toBe('POST');
    expect(sent[0].path).toBe('/api/v1/cluster/join');
    expect(sent[0].body).toEqual({ node_name: 'n2', seed_addresses: ['seed-a:7946'] });
  });

  it('leaves through POST /cluster/leave', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/cluster/leave': { status: 200, body: { status: { success: true } } },
    });
    const { result } = renderCluster();
    let res: Awaited<ReturnType<typeof result.current.leave>> | undefined;
    await act(async () => {
      res = await result.current.leave({ node_id: 'n2' });
    });
    expect(sent[0].method).toBe('POST');
    expect(sent[0].path).toBe('/api/v1/cluster/leave');
    expect(sent[0].body).toEqual({ node_id: 'n2' });
    expect(res?.data?.status?.success).toBe(true);
  });

  it("surfaces a refused leave with its status and the server's error", async () => {
    stubControlPlane({
      'POST /api/v1/cluster/leave': { status: 409, body: { error: 'node n2 is the leader' } },
    });
    const { result } = renderCluster();
    let res: Awaited<ReturnType<typeof result.current.leave>> | undefined;
    await act(async () => {
      res = await result.current.leave({ node_id: 'n2' });
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(409);
    expect(res?.error?.message).toBe('node n2 is the leader');
  });

  it('bootstrap does not replay the POST after a lost response', async () => {
    const fetchMock = stubLostResponse();
    const { result } = renderCluster();
    let res: Awaited<ReturnType<typeof result.current.bootstrap>> | undefined;
    await act(async () => {
      res = await result.current.bootstrap({ cluster_name: 'lab', node_name: 'n1' });
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(res?.success).toBe(false);
  }, 15000);

  it('join does not replay the POST after a lost response', async () => {
    const fetchMock = stubLostResponse();
    const { result } = renderCluster();
    let res: Awaited<ReturnType<typeof result.current.join>> | undefined;
    await act(async () => {
      res = await result.current.join({ node_name: 'n2', seed_addresses: ['seed-a:7946'] });
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(res?.success).toBe(false);
  }, 15000);

  it('leave does not replay the POST after a lost response', async () => {
    const fetchMock = stubLostResponse();
    const { result } = renderCluster();
    let res: Awaited<ReturnType<typeof result.current.leave>> | undefined;
    await act(async () => {
      res = await result.current.leave({ node_id: 'n2' });
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(res?.success).toBe(false);
  }, 15000);

  it('labels unknown enum values as Unknown', () => {
    expect(clusterStateLabel(undefined)).toBe('Unknown');
    expect(nodeRoleLabel(0)).toBe('Unknown');
    expect(nodeStateLabel(99 as NodeState)).toBe('Unknown');
  });
});
