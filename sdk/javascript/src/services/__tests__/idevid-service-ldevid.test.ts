/**
 * Unit tests for IDevIDService.createLDevID: the server routes
 * `POST /api/v1/idevid/ldevid` (pkg/webservice/v1/rest/idevid/router.go).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IDevIDService } from '../idevid-service.js';
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

describe('IDevIDService.createLDevID', () => {
  let service: IDevIDService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new IDevIDService(mockClient);
  });

  it('posts the request to /v1/idevid/ldevid', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: { status: { success: true }, certificatePem: 'PEM' },
    });

    const request = { template: { commonName: 'node-1' }, algorithm: 'ECDSA_P256' as const, overwrite: true };
    const result = await service.createLDevID(request);

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    const [url, body] = vi.mocked(mockClient.post).mock.calls[0]!;
    expect(url).toMatch(/\/v1\/idevid\/ldevid$/);
    expect(body).toEqual(request);
    expect(result.data?.certificatePem).toBe('PEM');
  });

  it('posts an empty body when called without a request', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });

    await service.createLDevID();

    const [url, body] = vi.mocked(mockClient.post).mock.calls[0]!;
    expect(url).toMatch(/\/v1\/idevid\/ldevid$/);
    expect(body).toEqual({});
  });
});
