/**
 * Unit tests for the ProxyService read routes (/api/v1/proxy, #2061).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ProxyService } from '../proxy-service.js';
import { ProxyService as IndexedProxyService } from '../index.js';
import { ProxyService as RootProxyService } from '../../index.js';
import type {
  GetProxyConfigResponse,
  GetProxyPoolResponse,
  GetProxyRouteResponse,
  GetProxyStatusResponse,
  GetProxyZoneMatrixResponse,
  ListProxyPoolsResponse,
  ListProxyRoutesResponse,
} from '../../index.js';
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

describe('ProxyService', () => {
  let service: ProxyService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new ProxyService(mockClient);
  });

  it('is exported from the services index', () => {
    expect(IndexedProxyService).toBe(ProxyService);
  });

  it('is exported from the package root with its response types', () => {
    expect(RootProxyService).toBe(ProxyService);
    const routes: ListProxyRoutesResponse | undefined = undefined;
    const route: GetProxyRouteResponse | undefined = undefined;
    const pools: ListProxyPoolsResponse | undefined = undefined;
    const pool: GetProxyPoolResponse | undefined = undefined;
    const config: GetProxyConfigResponse | undefined = undefined;
    const status: GetProxyStatusResponse | undefined = undefined;
    const matrix: GetProxyZoneMatrixResponse | undefined = undefined;
    expect([routes, route, pools, pool, config, status, matrix]).toHaveLength(7);
  });

  const reads: Array<{ name: string; call: (s: ProxyService) => Promise<unknown>; path: string; data: unknown }> = [
    {
      name: 'listRoutes',
      call: (s) => s.listRoutes(),
      path: '/v1/proxy/routes',
      data: { routes: [{ id: 'web', pathPrefix: '/app' }], version: '7' },
    },
    { name: 'getRoute', call: (s) => s.getRoute('a/b'), path: '/v1/proxy/routes/a%2Fb', data: { route: { id: 'a/b' } } },
    { name: 'listPools', call: (s) => s.listPools(), path: '/v1/proxy/pools', data: { pools: [], version: '7' } },
    { name: 'getPool', call: (s) => s.getPool('pool 1'), path: '/v1/proxy/pools/pool%201', data: { pool: { id: 'pool 1' } } },
    { name: 'getConfig', call: (s) => s.getConfig(), path: '/v1/proxy/config', data: { routes: [], pools: [], version: '7' } },
    {
      name: 'getStatus',
      call: (s) => s.getStatus(),
      path: '/v1/proxy/status',
      data: { version: '7', routeCount: 2, poolCount: 1, updatedAt: '1700000000' },
    },
    {
      name: 'getZoneMatrix',
      call: (s) => s.getZoneMatrix(),
      path: '/v1/proxy/zone-matrix',
      data: { zones: ['management'], pairs: [{ from: 'management', to: 'tenant', services: [] }] },
    },
  ];

  for (const read of reads) {
    it(`${read.name} gets ${read.path}`, async () => {
      const response = { success: true, data: read.data };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      const result = await read.call(service);

      expect(mockClient.get).toHaveBeenCalledTimes(1);
      expect(mockClient.get).toHaveBeenCalledWith(read.path);
      expect(result).toEqual(response);
      expect(mockClient.post).not.toHaveBeenCalled();
      expect(mockClient.put).not.toHaveBeenCalled();
      expect(mockClient.delete).not.toHaveBeenCalled();
    });
  }
});
