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
    const call = vi.mocked(mockClient.post).mock.calls[0];
    if (!call) {
      throw new Error('post was not called');
    }
    const [url, body] = call;
    expect(url).toMatch(/\/v1\/idevid\/ldevid$/);
    expect(body).toEqual({ ...request, algorithm: 'DEVICE_KEY_ALGORITHM_ECDSA_P256' });
    expect(result.data?.certificatePem).toBe('PEM');
  });

  function postedBody(): unknown {
    const call = vi.mocked(mockClient.post).mock.calls[0];
    if (!call) {
      throw new Error('post was not called');
    }
    return call[1];
  }

  it('sends the algorithm as the proto enum name', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });

    await service.createLDevID({ algorithm: 'RSA_3072' });

    expect(postedBody()).toEqual({ algorithm: 'DEVICE_KEY_ALGORITHM_RSA_3072' });
  });

  it('sends nondefault algorithms as protobuf enum names', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });

    await service.createLDevID({ algorithm: 'ECDSA_P384' });
    await service.createLDevID({ algorithm: 'RSA_3072' });

    const bodies = vi.mocked(mockClient.post).mock.calls.map((call) => call[1]);
    expect(bodies).toEqual([
      { algorithm: 'DEVICE_KEY_ALGORITHM_ECDSA_P384' },
      { algorithm: 'DEVICE_KEY_ALGORITHM_RSA_3072' },
    ]);
  });

  it('posts no algorithm key when none is given', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });

    await service.createLDevID({ overwrite: true });

    const body = postedBody();
    expect(body).toEqual({ overwrite: true });
    expect(Object.prototype.hasOwnProperty.call(body, 'algorithm')).toBe(false);
  });

  it('posts an empty body when called without a request', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { status: { success: true } } });

    await service.createLDevID();

    const call = vi.mocked(mockClient.post).mock.calls[0];
    if (!call) {
      throw new Error('post was not called');
    }
    const [url, body] = call;
    expect(url).toMatch(/\/v1\/idevid\/ldevid$/);
    expect(body).toEqual({});
  });
});
