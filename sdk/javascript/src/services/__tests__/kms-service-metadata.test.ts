/**
 * KMSService key metadata tests (#2057).
 *
 * The server serves the whole-key status at GET /api/v1/kms/keys/{name}/metadata
 * (pkg/webservice/v1/rest/kms/types.go KeyMetadataResponse). These tests pin
 * the SDK to that path.
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

describe('KMSService key metadata (#2057)', () => {
  let mockClient: ApiClient;
  let service: KMSService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new KMSService(mockClient);
  });

  it('getKeyMetadata GETs /v1/kms/keys/{name}/metadata with the name escaped', async () => {
    const answer = {
      success: true,
      data: {
        key_id: 'team/key 1',
        algorithm: 'AES_256_GCM',
        status: 'DISABLED',
        version: 2,
        exportable: false,
        deletion_protection: false,
      },
    };
    vi.mocked(mockClient.get).mockResolvedValue(answer);
    const res = await service.getKeyMetadata('team/key 1');
    expect(mockClient.get).toHaveBeenCalledTimes(1);
    const url = vi.mocked(mockClient.get).mock.calls[0]?.[0] as string;
    expect(url.endsWith('/v1/kms/keys/team%2Fkey%201/metadata')).toBe(true);
    expect(res).toEqual(answer);
  });
});
