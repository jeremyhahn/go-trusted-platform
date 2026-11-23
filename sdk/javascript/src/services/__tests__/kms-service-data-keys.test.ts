/**
 * KMSService data-key wire tests (#2057).
 *
 * The server serves GenerateDataKey at POST /api/v1/kms/data-keys and
 * GenerateWrappedDataKey at POST /api/v1/kms/data-keys/wrapped
 * (pkg/webservice/v1/rest/kms/router.go). These tests pin the SDK to
 * those paths.
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

describe('KMSService data keys', () => {
  let mockClient: ApiClient;
  let service: KMSService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
    service = new KMSService(mockClient);
  });

  it('generateDataKey POSTs the snake_case body to /v1/kms/data-keys', async () => {
    await service.generateDataKey({ keyId: 'kek-1', algorithm: 'AES_256_GCM', keySize: 256, context: 'Y3R4' });
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/kms/data-keys', {
      key_id: 'kek-1',
      algorithm: 'AES_256_GCM',
      key_size: 256,
      context: 'Y3R4',
    });
  });

  it('generateDataKey does not send absent optional fields', async () => {
    await service.generateDataKey({ keyId: 'kek-1' });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/kms/data-keys', { key_id: 'kek-1' });
  });

  it('generateWrappedDataKey POSTs the snake_case body to /v1/kms/data-keys/wrapped', async () => {
    await service.generateWrappedDataKey({
      wrappingKeyId: 'wk-1',
      keyAlgorithm: 'AES_256_GCM',
      keySize: 256,
      context: 'Y3R4',
    });
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/kms/data-keys/wrapped', {
      wrapping_key_id: 'wk-1',
      key_algorithm: 'AES_256_GCM',
      key_size: 256,
      context: 'Y3R4',
    });
  });

  it('generateWrappedDataKey does not send absent optional fields', async () => {
    await service.generateWrappedDataKey({ wrappingKeyId: 'wk-1' });
    expect(mockClient.post).toHaveBeenCalledWith('/v1/kms/data-keys/wrapped', { wrapping_key_id: 'wk-1' });
  });

  it('generateDataKey maps the snake_case answer to camelCase', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: { key_id: 'kek-1', plaintext_key: 'cA==', encrypted_key: 'ZQ==' },
    });
    const res = await service.generateDataKey({ keyId: 'kek-1' });
    expect(res.success).toBe(true);
    expect(res.data?.keyId).toBe('kek-1');
    expect(res.data?.plaintextKey).toBe('cA==');
    expect(res.data?.encryptedKey).toBe('ZQ==');
  });

  it('generateWrappedDataKey maps the snake_case answer to camelCase', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: { wrapping_key_id: 'wk-1', wrapped_key: 'dw==' },
    });
    const res = await service.generateWrappedDataKey({ wrappingKeyId: 'wk-1' });
    expect(res.success).toBe(true);
    expect(res.data?.wrappingKeyId).toBe('wk-1');
    expect(res.data?.wrappedKey).toBe('dw==');
  });

  it('returns a refused answer unchanged', async () => {
    const refused = { success: false, error: { code: 'DENIED', message: 'kms: denied' } };
    vi.mocked(mockClient.post).mockResolvedValue(refused);
    expect(await service.generateDataKey({ keyId: 'kek-1' })).toEqual(refused);
    expect(await service.generateWrappedDataKey({ wrappingKeyId: 'wk-1' })).toEqual(refused);
  });
});
