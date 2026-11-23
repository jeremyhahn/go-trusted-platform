/**
 * KMSService batch route tests (#2057).
 *
 * The server serves BatchEncrypt at POST /api/v1/kms/batch-encrypt and
 * BatchDecrypt at POST /api/v1/kms/batch-decrypt
 * (pkg/webservice/v1/rest/kms/handlers_batch.go) with snake_case bodies.
 * These tests pin the SDK to those paths and names.
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

describe('KMSService batch routes (#2057)', () => {
  let mockClient: ApiClient;
  let service: KMSService;
  const answer = {
    success: true,
    data: {
      key_id: 'kek',
      results: [
        { item_id: 'a', ciphertext: 'Y3Q=', nonce: 'bm9u' },
        { item_id: 'b', error: 'refused' },
      ],
      success_count: 1,
      failure_count: 1,
    },
  };

  beforeEach(() => {
    mockClient = createMockApiClient();
    vi.mocked(mockClient.post).mockResolvedValue(answer);
    service = new KMSService(mockClient);
  });

  it('batchEncrypt POSTs the snake_case body to /v1/kms/batch-encrypt', async () => {
    const res = await service.batchEncrypt({
      keyId: 'kek',
      items: [
        { itemId: 'a', plaintext: 'b25l' },
        { itemId: 'b', plaintext: 'dHdv' },
      ],
    });
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/kms/batch-encrypt', {
      key_id: 'kek',
      items: [
        { item_id: 'a', plaintext: 'b25l' },
        { item_id: 'b', plaintext: 'dHdv' },
      ],
    });
    expect(res).toEqual(answer);
  });

  it('batchDecrypt POSTs the snake_case body to /v1/kms/batch-decrypt', async () => {
    const res = await service.batchDecrypt({
      keyId: 'kek',
      items: [{ itemId: 'a', ciphertext: 'Y3Q=', nonce: 'bm9u' }],
    });
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/kms/batch-decrypt', {
      key_id: 'kek',
      items: [{ item_id: 'a', ciphertext: 'Y3Q=', nonce: 'bm9u' }],
    });
    expect(res).toEqual(answer);
  });

  it('batchDecrypt sends no nonce when the item has none', async () => {
    await service.batchDecrypt({ keyId: 'kek', items: [{ itemId: 'a', ciphertext: 'Y3Q=' }] });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/kms/batch-decrypt', {
      key_id: 'kek',
      items: [{ item_id: 'a', ciphertext: 'Y3Q=' }],
    });
  });
});
