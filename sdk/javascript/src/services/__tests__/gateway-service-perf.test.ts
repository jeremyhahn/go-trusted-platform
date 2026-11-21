/**
 * Unit tests for GatewayService.getPerfFlows (#2052).
 *
 * The webservice serves the flow-programming benchmark as
 * `POST /api/v1/gateway/perf/flows`: it installs temporary flows, so it is a
 * write and never a GET. The path and body are pinned here.
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

describe('GatewayService perf flows', () => {
  let service: GatewayService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new GatewayService(mockClient);
  });

  function expectOnlyPost(path: string, body: unknown): void {
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith(path, body);
    expect(mockClient.get).not.toHaveBeenCalled();
    expect(mockClient.put).not.toHaveBeenCalled();
    expect(mockClient.patch).not.toHaveBeenCalled();
    expect(mockClient.delete).not.toHaveBeenCalled();
  }

  it('getPerfFlows posts the run parameters to /v1/gateway/perf/flows', async () => {
    const response = {
      success: true,
      data: { installed: 1000, durationNs: '2500000', flowsPerSecond: 400000, batched: true, bridge: 'br-int' },
    };
    vi.mocked(mockClient.post).mockResolvedValue(response);

    const result = await service.getPerfFlows({ count: 1000, batch: true });

    expect(result).toBe(response);
    expectOnlyPost('/v1/gateway/perf/flows', { count: 1000, batch: true });
  });

  it('getPerfFlows with no arguments posts an empty body (server defaults)', async () => {
    const response = { success: true, data: null };
    vi.mocked(mockClient.post).mockResolvedValue(response);

    const result = await service.getPerfFlows();

    expect(result).toBe(response);
    expectOnlyPost('/v1/gateway/perf/flows', {});
  });
});
