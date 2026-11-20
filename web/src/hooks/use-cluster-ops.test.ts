import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const service = {
  getStatus: vi.fn(),
  listNodes: vi.fn(),
  bootstrap: vi.fn(),
  join: vi.fn(),
  leave: vi.fn(),
};

vi.mock('trusted-platform-sdk', () => ({
  useCluster: () => service,
}));

import { useClusterOps } from './use-cluster-ops';

const cluster = {
  id: 'c-1',
  name: 'lab',
  state: 'CLUSTER_STATE_HEALTHY',
  leaderId: 'n-1',
  totalNodes: 1,
  healthyNodes: 1,
};
const node = { id: 'n-1', name: 'node-a', address: '10.0.0.1', port: 7946, role: 'NODE_ROLE_LEADER', state: 'NODE_STATE_ACTIVE' };

function ok<T>(data: T) {
  return { success: true, data };
}

function fail(message: string, code = 'SERVICE_UNAVAILABLE') {
  return { success: false, error: { code, message } };
}

/** ClusterService GetStatus, ListNodes, Bootstrap, Join and Leave (#2043). */
describe('useClusterOps', () => {
  beforeEach(() => {
    for (const fn of Object.values(service)) fn.mockReset();
    service.getStatus.mockResolvedValue(ok({ cluster, localNode: node, nodes: [node] }));
    service.listNodes.mockResolvedValue(ok({ nodes: [node], total: 1 }));
  });

  afterEach(() => {
    cleanup();
  });

  it('loads the status and the nodes on mount and shortens the enum names', async () => {
    const { result } = renderHook(() => useClusterOps());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(service.getStatus).toHaveBeenCalledTimes(1);
    expect(service.listNodes).toHaveBeenCalledTimes(1);
    expect(result.current.available).toBe(true);
    expect(result.current.status?.cluster?.state).toBe('HEALTHY');
    expect(result.current.status?.localNode?.id).toBe('n-1');
    expect(result.current.nodes).toHaveLength(1);
    expect(result.current.nodes[0]?.role).toBe('LEADER');
    expect(result.current.nodes[0]?.state).toBe('ACTIVE');
  });

  it('reports the server reason and stays unavailable when the cluster is not configured', async () => {
    service.getStatus.mockResolvedValue(fail('cluster service not configured'));
    service.listNodes.mockResolvedValue(fail('cluster service not configured'));
    const { result } = renderHook(() => useClusterOps());
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.available).toBe(false);
    expect(result.current.unavailableReason).toBe('cluster service not configured');
    expect(result.current.status).toBeNull();
    expect(result.current.nodes).toEqual([]);
  });

  it('bootstrap sends the form and reloads the status', async () => {
    service.bootstrap.mockResolvedValue(ok({ status: { success: true }, cluster, node }));
    const { result } = renderHook(() => useClusterOps());
    await waitFor(() => expect(result.current.loading).toBe(false));
    await act(() => result.current.bootstrap({ clusterName: 'lab', nodeName: 'node-a' }));
    expect(service.bootstrap).toHaveBeenCalledWith({ clusterName: 'lab', nodeName: 'node-a' });
    expect(service.getStatus).toHaveBeenCalledTimes(2);
    expect(result.current.notice).toBe('Cluster lab bootstrapped');
    expect(result.current.error).toBeNull();
  });

  it('join splits the seed addresses and refuses an empty list without calling the server', async () => {
    service.join.mockResolvedValue(ok({ status: { success: true }, cluster, node }));
    const { result } = renderHook(() => useClusterOps());
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(() => result.current.join({ seedAddresses: ' ' }));
    expect(service.join).not.toHaveBeenCalled();
    expect(result.current.error).toBe('Enter at least one seed address');

    await act(() => result.current.join({ nodeName: 'node-b', seedAddresses: '10.0.0.1:7946, 10.0.0.2:7946' }));
    expect(service.join).toHaveBeenCalledWith({
      nodeName: 'node-b',
      seedAddresses: ['10.0.0.1:7946', '10.0.0.2:7946'],
    });
    expect(result.current.notice).toBe('Joined cluster lab');
  });

  it('leave posts the node and force flag and shows a refused status message', async () => {
    service.leave.mockResolvedValue(ok({ status: { success: false, message: 'last voter cannot leave' } }));
    const { result } = renderHook(() => useClusterOps());
    await waitFor(() => expect(result.current.loading).toBe(false));
    await act(() => result.current.leave({ nodeId: 'n-1', force: true }));
    expect(service.leave).toHaveBeenCalledWith({ nodeId: 'n-1', force: true });
    expect(result.current.error).toBe('last voter cannot leave');
    expect(result.current.notice).toBeNull();
  });

  it('shows the server error of a refused write', async () => {
    service.bootstrap.mockResolvedValue(fail('cluster already bootstrapped', 'CONFLICT'));
    const { result } = renderHook(() => useClusterOps());
    await waitFor(() => expect(result.current.loading).toBe(false));
    await act(() => result.current.bootstrap({ clusterName: 'lab' }));
    expect(result.current.error).toBe('cluster already bootstrapped');
    expect(result.current.busy).toBe(false);
  });
});
