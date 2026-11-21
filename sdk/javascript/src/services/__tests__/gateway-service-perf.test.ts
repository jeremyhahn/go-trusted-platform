/**
 * Unit tests for GatewayService.getPerfFlows (#2052).
 *
 * The webservice serves the flow-programming benchmark as
 * `POST /api/v1/gateway/perf/flows`: it installs temporary flows, so it is a
 * write and never a GET. The path and body are pinned here.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GatewayService } from '../gateway-service.js';
import { ApiClient } from '../../client/api-client.js';

const NO_RETRY = { retry: { enabled: false } };

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

  function expectOnlyPost(path: string, body: unknown, options?: unknown): void {
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    if (options === undefined) {
      expect(mockClient.post).toHaveBeenCalledWith(path, body);
    } else {
      expect(mockClient.post).toHaveBeenCalledWith(path, body, options);
    }
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
    expectOnlyPost('/v1/gateway/perf/flows', { count: 1000, batch: true }, NO_RETRY);
  });

  it('getPerfFlows with no arguments posts an empty body (server defaults)', async () => {
    const response = { success: true, data: null };
    vi.mocked(mockClient.post).mockResolvedValue(response);

    const result = await service.getPerfFlows();

    expect(result).toBe(response);
    expectOnlyPost('/v1/gateway/perf/flows', {}, NO_RETRY);
  });
});

describe('GatewayService perf flows over the real ApiClient', () => {
  it('a lost response is not re-sent', async () => {
    // The client keeps its default retry policy (maxRetries 3,
    // retryOnNetworkError true): only the per-request opt-out stops a
    // confirmed benchmark from running twice (#2179 Codex).
    const fetchImpl = vi.fn(() => Promise.reject(new TypeError('fetch failed')));
    const service = new GatewayService(
      new ApiClient({
        baseUrl: 'https://platform.test/api',
        fetch: fetchImpl as unknown as typeof fetch,
        retry: { initialDelayMs: 1, maxDelayMs: 1 },
      }),
    );

    await service.getPerfFlows({ count: 1000, batch: true }).catch(() => undefined);

    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});
