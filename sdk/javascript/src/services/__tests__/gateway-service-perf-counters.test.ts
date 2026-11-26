/**
 * Unit tests for GatewayService.getPerfDatapath and getPerfConntrack (#2052).
 *
 * The webservice serves both counter reads as GETs:
 * `GET /api/v1/gateway/perf/datapath?bridge=` and
 * `GET /api/v1/gateway/perf/conntrack?zone=`. The paths and queries are pinned here.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GatewayService } from '../gateway-service.js';
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

describe('GatewayService perf counters', () => {
  let service: GatewayService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new GatewayService(mockClient);
  });

  function expectOnlyGet(path: string): void {
    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith(path);
    expect(mockClient.post).not.toHaveBeenCalled();
    expect(mockClient.put).not.toHaveBeenCalled();
    expect(mockClient.patch).not.toHaveBeenCalled();
    expect(mockClient.delete).not.toHaveBeenCalled();
  }

  it('getPerfDatapath() reads the default bridge', async () => {
    const response = {
      success: true,
      data: { hits: '10', misses: '2', hwOffloadEnabled: true, datapathType: 'system', bridge: 'br-int' },
    };
    vi.mocked(mockClient.get).mockResolvedValue(response);

    const result = await service.getPerfDatapath();

    expect(result).toBe(response);
    expectOnlyGet('/v1/gateway/perf/datapath');
  });

  it('getPerfDatapath(bridge) encodes the bridge in the query', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

    await service.getPerfDatapath('br int');

    expectOnlyGet('/v1/gateway/perf/datapath?bridge=br%20int');
  });

  it('getPerfConntrack() summarizes every zone', async () => {
    const response = { success: true, data: { totalEntries: '42', perZone: { '7': '12' } } };
    vi.mocked(mockClient.get).mockResolvedValue(response);

    const result = await service.getPerfConntrack();

    expect(result).toBe(response);
    expectOnlyGet('/v1/gateway/perf/conntrack');
  });

  it('getPerfConntrack(0) sends zone 0', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

    await service.getPerfConntrack(0);

    expectOnlyGet('/v1/gateway/perf/conntrack?zone=0');
  });
});
