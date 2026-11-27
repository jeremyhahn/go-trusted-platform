/**
 * PlatformService reaches the daemon services routes the server serves
 * under /v1/platform/services (#2047): list, status, start, stop, restart.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PlatformService } from '../platform-service.js';
import { ApiClient } from '../../client/api-client.js';

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
  } as unknown as ApiClient;
}

describe('PlatformService daemon services', () => {
  let mockClient: ApiClient;
  let service: PlatformService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new PlatformService(mockClient);
  });

  it('listServices GETs /v1/platform/services and returns the snake_case list', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({
      success: true,
      data: {
        services: [
          {
            name: 'acme',
            status: 'running',
            started_at: '2026-11-21T00:00:00Z',
            uptime: '1h0m0s',
            start_count: 2,
            stop_count: 1,
          },
        ],
        count: 1,
        timestamp: 1763683200,
      },
    });

    const res = await service.listServices();

    expect(mockClient.get).toHaveBeenCalledWith('/v1/platform/services');
    expect(res.data?.services[0]?.start_count).toBe(2);
    expect(res.data?.count).toBe(1);
  });

  it('getServiceStatus GETs /v1/platform/services/{name}', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({
      success: true,
      data: { name: 'acme', status: 'running', start_count: 1, stop_count: 0 },
    });

    const res = await service.getServiceStatus('acme');

    expect(mockClient.get).toHaveBeenCalledWith('/v1/platform/services/acme');
    expect(res.data?.status).toBe('running');
  });

  it('getServiceStatus encodes the service name as one path segment', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({
      success: true,
      data: { name: 'a b/c', status: 'unknown', start_count: 0, stop_count: 0 },
    });

    await service.getServiceStatus('a b/c');

    expect(mockClient.get).toHaveBeenCalledWith('/v1/platform/services/a%20b%2Fc');
  });

  it.each([
    ['start', (s: PlatformService) => s.startService('dns')],
    ['stop', (s: PlatformService) => s.stopService('dns')],
    ['restart', (s: PlatformService) => s.restartService('dns')],
  ] as const)('%sService POSTs /v1/platform/services/dns/%s with {}', async (verb, call) => {
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: { service: 'dns', action: verb, success: true, message: 'ok' },
    });

    const res = await call(service);

    expect(mockClient.post).toHaveBeenCalledWith(`/v1/platform/services/dns/${verb}`, {}, { retry: { enabled: false } });
    expect(res.data?.action).toBe(verb);
  });

  it('restartService sends one POST when the reply is lost', async () => {
    const fetchImpl = vi.fn(() => Promise.reject(new TypeError('network')));
    const client = new ApiClient({
      baseUrl: 'http://api.test',
      fetch: fetchImpl as unknown as typeof fetch,
      retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 2 },
    });
    await new PlatformService(client).restartService('dns').catch(() => undefined);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('passes a refused start through unchanged', async () => {
    const refused = {
      success: false,
      error: { code: 'FAILED_PRECONDITION', message: 'already running', status: 409 },
    };
    vi.mocked(mockClient.post).mockResolvedValue(refused);

    const res = await service.startService('dns');

    expect(res).toEqual(refused);
  });
});
