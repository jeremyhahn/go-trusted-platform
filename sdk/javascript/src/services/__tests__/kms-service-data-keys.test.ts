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

  it('generateDataKey POSTs /v1/kms/data-keys', async () => {
    await service.generateDataKey({ keyId: 'kek-1' });
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/kms/data-keys', { keyId: 'kek-1' });
  });

  it('generateWrappedDataKey POSTs /v1/kms/data-keys/wrapped', async () => {
    await service.generateWrappedDataKey({ wrappingKeyId: 'wk-1' });
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/kms/data-keys/wrapped', {
      wrappingKeyId: 'wk-1',
    });
  });
});
