/**
 * SDNService gateway IPAM pool tests: create, list, get, update and delete
 * against /v1/sdn/gateway/ipam/pools.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SDNService } from '../sdn-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type {
  ListSDNIPAMAllocationsResponse,
  ListSDNIPAMPoolsResponse,
  SDNIPAMPool,
  SDNIPAMPoolRequest,
} from '../../types/sdn-ipam.js';

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

const pool: SDNIPAMPool = {
  id: 'pool-a',
  name: 'pool-a',
  cidr: '192.0.2.0/24',
  gateway: '192.0.2.1',
  zone: 'control-plane',
  total: 254,
  allocated: 2,
  available: 252,
};

describe('SDNService IPAM pools', () => {
  let service: SDNService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new SDNService(mockClient);
  });

  it('creates a pool on POST /v1/sdn/gateway/ipam/pools with the body unchanged', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: pool });
    const body: SDNIPAMPoolRequest = {
      name: 'pool-a',
      cidr: '192.0.2.0/24',
      gateway: '192.0.2.1',
      zone: 'control-plane',
      default_lease_duration_nanos: 3600000000000,
      reserved: ['192.0.2.0/30'],
      range_start: '192.0.2.10',
      range_end: '192.0.2.200',
    };

    const result = await service.createIPAMPool(body);

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/sdn/gateway/ipam/pools', body);
    expect(result).toEqual({ success: true, data: pool });
  });

  it('lists pools on GET /v1/sdn/gateway/ipam/pools', async () => {
    const data: ListSDNIPAMPoolsResponse = {
      pools: [pool],
      count: 1,
      timestamp: '2026-11-23T00:00:00Z',
    };
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data });

    const result = await service.listIPAMPools();

    expect(mockClient.get).toHaveBeenCalledWith('/v1/sdn/gateway/ipam/pools');
    expect(result.data).toEqual(data);
  });

  it('lists the pools of one zone with ?zone=', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { pools: [], count: 0 } });

    await service.listIPAMPools({ zone: 'control-plane' });

    expect(mockClient.get).toHaveBeenCalledWith('/v1/sdn/gateway/ipam/pools?zone=control-plane');
  });

  it('gets a pool on GET /v1/sdn/gateway/ipam/pools/{id} with the id encoded', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: pool });

    const result = await service.getIPAMPool('pool/a');

    expect(mockClient.get).toHaveBeenCalledWith('/v1/sdn/gateway/ipam/pools/pool%2Fa');
    expect(result.data).toEqual(pool);
  });

  it('updates a pool on PUT /v1/sdn/gateway/ipam/pools/{id} with the body', async () => {
    vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: pool });
    const body: SDNIPAMPoolRequest = { name: 'pool-a', description: 'lab', range_start: '' };

    await service.updateIPAMPool('pool-a', body);

    expect(mockClient.put).toHaveBeenCalledWith('/v1/sdn/gateway/ipam/pools/pool-a', body);
  });

  it('deletes a pool on DELETE /v1/sdn/gateway/ipam/pools/{id}', async () => {
    const data = {
      resource_id: 'pool-a',
      resource_type: 'ipam_pool',
      action: 'delete',
      success: true,
    };
    vi.mocked(mockClient.delete).mockResolvedValue({ success: true, data });

    const result = await service.deleteIPAMPool('pool-a');

    expect(mockClient.delete).toHaveBeenCalledWith('/v1/sdn/gateway/ipam/pools/pool-a');
    expect(result.data).toEqual(data);
  });

  it('lists the allocations of one pool with GET /sdn/gateway/ipam/allocations?pool_id=', async () => {
    const data: ListSDNIPAMAllocationsResponse = {
      allocations: [{ ip: '192.0.2.10', pool_id: 'pool-1', status: 'allocated' }],
      count: 1,
    };
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data });

    const result = await service.listIPAMAllocations({ poolId: 'pool-1' });

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    const url = new URL(vi.mocked(mockClient.get).mock.calls[0]?.[0] as string, 'https://api.example.com');
    expect(url.pathname).toBe('/v1/sdn/gateway/ipam/allocations');
    expect(url.searchParams.get('pool_id')).toBe('pool-1');
    expect(result.data).toEqual(data);
  });

  it('lists every allocation when no pool is given', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { allocations: [], count: 0 } });

    await service.listIPAMAllocations();

    expect(mockClient.get).toHaveBeenCalledWith('/v1/sdn/gateway/ipam/allocations');
  });

  describe('errors', () => {
    type Verb = 'get' | 'post' | 'put' | 'delete';
    const cases: Array<[string, Verb, (s: SDNService) => Promise<unknown>]> = [
      ['createIPAMPool', 'post', (s) => s.createIPAMPool({ name: 'p', cidr: '192.0.2.0/24' })],
      ['listIPAMPools', 'get', (s) => s.listIPAMPools()],
      ['getIPAMPool', 'get', (s) => s.getIPAMPool('pool-a')],
      ['updateIPAMPool', 'put', (s) => s.updateIPAMPool('pool-a', { name: 'p' })],
      ['deleteIPAMPool', 'delete', (s) => s.deleteIPAMPool('pool-a')],
      ['listIPAMAllocations', 'get', (s) => s.listIPAMAllocations({ poolId: 'pool-a' })],
    ];

    it.each(cases)('%s propagates a transport rejection', async (_name, verb, call) => {
      const failure = new Error('transport down');
      vi.mocked(mockClient[verb]).mockRejectedValue(failure);

      await expect(call(service)).rejects.toBe(failure);
    });

    it.each(cases)('%s returns an unsuccessful response unchanged', async (_name, verb, call) => {
      const response = { success: false, error: { code: 'UNAVAILABLE', message: 'gateway not running' } };
      vi.mocked(mockClient[verb]).mockResolvedValue(response);

      await expect(call(service)).resolves.toBe(response);
    });
  });
});
