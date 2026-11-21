/**
 * Unit tests for the platform cluster service routes
 * (pkg/api/daemon/cluster_rest.go: /api/v1/cluster/*).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PlatformClusterService } from '../platform-cluster-service.js';
import { PlatformClusterService as IndexedPlatformClusterService } from '../index.js';
import { PlatformClusterService as RootPlatformClusterService } from '../../index.js';
import type {
  PlatformClusterStatusResponse,
  PlatformClusterNodesResponse,
  PlatformClusterMembershipResponse,
  PlatformClusterLeaveResponse,
} from '../../index.js';
import { PlatformClient } from '../../client/platform-client.js';
import type { ApiClient } from '../../client/api-client.js';

function createMockApiClient(): ApiClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'https://api.example.com',
  } as unknown as ApiClient;
}

describe('PlatformClusterService', () => {
  let service: PlatformClusterService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new PlatformClusterService(mockClient);
  });

  it('is exported from the services index and the package root, and wired as client.platformCluster', () => {
    expect(IndexedPlatformClusterService).toBe(PlatformClusterService);
    expect(RootPlatformClusterService).toBe(PlatformClusterService);
    const status: PlatformClusterStatusResponse | undefined = undefined;
    const nodes: PlatformClusterNodesResponse | undefined = undefined;
    const membership: PlatformClusterMembershipResponse | undefined = undefined;
    const left: PlatformClusterLeaveResponse | undefined = undefined;
    expect([status, nodes, membership, left]).toEqual([undefined, undefined, undefined, undefined]);

    const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
    expect(client.platformCluster).toBeInstanceOf(PlatformClusterService);
  });

  it('getStatus gets /v1/cluster/status', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { cluster: { name: 'alpha' } } });

    const result = await service.getStatus();

    expect(result.success).toBe(true);
    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/cluster/status');
  });

  it('listNodes gets /v1/cluster/nodes', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { nodes: [], total: 0 } });

    await service.listNodes();

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/cluster/nodes');
  });

  it('bootstrap posts /v1/cluster/bootstrap with the request body', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });
    const body = { cluster_name: 'alpha', node_name: 'node-1' };

    await service.bootstrap(body);

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/cluster/bootstrap', body);
  });

  it('join posts /v1/cluster/join with the request body', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });
    const body = { node_name: 'node-1', seed_addresses: ['seed-a:7001'] };

    await service.join(body);

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/cluster/join', body);
  });

  it('leave posts /v1/cluster/leave with the request body', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });
    const body = { node_id: '2', force: true };

    await service.leave(body);

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/cluster/leave', body);
  });

  it('propagates a transport error unchanged', async () => {
    const failure = new Error('503 Service Unavailable: cluster service not configured');
    vi.mocked(mockClient.get).mockRejectedValue(failure);

    await expect(service.getStatus()).rejects.toBe(failure);
  });
});
