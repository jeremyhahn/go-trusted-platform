/**
 * KMSService.hmac and verifyHMAC (#2057): each is asserted against the path
 * the server mounts (pkg/webservice/v1/rest/kms/router.go: POST
 * /api/v1/kms/hmac/{name} and /api/v1/kms/hmac/{name}/verify) and the body it
 * decodes (pkg/webservice/v1/rest/kms/types.go: { data, hash } and
 * { data, hmac, hash }), with the key name taken from the path.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { KMSService } from '../kms-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import type { HMACResponse, VerifyHMACResponse } from '../../types/kms.js';

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

describe('KMSService HMAC routes (#2057)', () => {
  let client: ApiClient;
  let service: KMSService;

  beforeEach(() => {
    client = createMockApiClient();
    service = new KMSService(client);
  });

  it('hmac posts /v1/kms/hmac/{name} with the key name encoded and { data, hash }', async () => {
    vi.mocked(client.post).mockResolvedValue({ success: true, data: {} } as ApiResponse<HMACResponse>);

    await service.hmac({ keyId: 'k 1/x', message: 'aGk=', hashAlgorithm: 'SHA384' });

    expect(client.post).toHaveBeenCalledTimes(1);
    const [url, body] = vi.mocked(client.post).mock.calls[0]!;
    expect(url).toBe('/v1/kms/hmac/k%201%2Fx');
    expect(body).toEqual({ data: 'aGk=', hash: 'SHA384' });
  });

  it('hmac sends only data when no hash algorithm is given', async () => {
    vi.mocked(client.post).mockResolvedValue({ success: true, data: {} } as ApiResponse<HMACResponse>);

    await service.hmac({ keyId: 'k1', message: 'aGk=' });

    expect(client.post).toHaveBeenCalledTimes(1);
    const [url, body] = vi.mocked(client.post).mock.calls[0]!;
    expect(url).toBe('/v1/kms/hmac/k1');
    expect(Object.keys(body as object)).toEqual(['data']);
    expect(body).toEqual({ data: 'aGk=' });
  });

  it('verifyHMAC posts /v1/kms/hmac/{name}/verify with { data, hmac, hash } and no version', async () => {
    vi.mocked(client.post).mockResolvedValue({ success: true, data: {} } as ApiResponse<VerifyHMACResponse>);

    await service.verifyHMAC({
      keyId: 'k1',
      message: 'aGk=',
      hmac: 'dGFn',
      hashAlgorithm: 'SHA256',
      keyVersion: 2,
    });

    expect(client.post).toHaveBeenCalledTimes(1);
    const [url, body] = vi.mocked(client.post).mock.calls[0]!;
    expect(url).toBe('/v1/kms/hmac/k1/verify');
    expect(body).toEqual({ data: 'aGk=', hmac: 'dGFn', hash: 'SHA256' });
    expect(Object.keys(body as object).sort()).toEqual(['data', 'hash', 'hmac']);
  });

  it('returns an error response from post unchanged', async () => {
    const failure = {
      success: false,
      error: { code: 'NOT_FOUND', message: 'no key', status: 404 },
    } as unknown as ApiResponse<HMACResponse>;
    vi.mocked(client.post).mockResolvedValue(failure);

    const hmacResult = await service.hmac({ keyId: 'k1', message: 'aGk=' });
    expect(hmacResult).toBe(failure);

    const verifyResult = await service.verifyHMAC({ keyId: 'k1', message: 'aGk=', hmac: 'dGFn' });
    expect(verifyResult).toBe(failure);
  });
});
