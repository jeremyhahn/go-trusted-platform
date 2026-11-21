/**
 * KMS encrypt and decrypt path tests (#2057).
 *
 * The server serves POST /api/v1/kms/encrypt/{name} and
 * POST /api/v1/kms/decrypt/{name} (pkg/webservice/v1/rest/kms/router.go);
 * the key name is the path segment and the body is sent unchanged.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { KMSService } from '../kms-service.js';
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

describe('KMSService encrypt and decrypt paths', () => {
  let mockClient: ApiClient;
  let service: KMSService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new KMSService(mockClient);
  });

  it('encrypt POSTs the served /v1/kms/encrypt/{name} route', async () => {
    const request = { keyId: 'k1', plaintext: 'aGk=' };
    await service.encrypt(request);
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/kms/encrypt/k1', {
      keyId: 'k1',
      plaintext: 'aGk=',
    });
  });

  it('decrypt POSTs the served /v1/kms/decrypt/{name} route', async () => {
    const request = { keyId: 'k1', ciphertext: 'abc' };
    await service.decrypt(request);
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/kms/decrypt/k1', {
      keyId: 'k1',
      ciphertext: 'abc',
    });
  });

  it('encrypt encodes the key name path segment', async () => {
    await service.encrypt({ keyId: 'a/b', plaintext: 'aGk=' });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/kms/encrypt/a%2Fb', {
      keyId: 'a/b',
      plaintext: 'aGk=',
    });
  });
});
