/**
 * IAMService.rotateAppSecret wire test (#2054).
 *
 * The server rotates an application secret at
 * POST /api/v1/iam/tenants/{tenant}/apps/{id}/rotate
 * (pkg/webservice/v1/rest/iam/router.go). The SDK must post to that
 * route, not the unserved /rotate-secret path.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IAMService } from '../iam-service.js';
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

describe('IAMService.rotateAppSecret', () => {
  let mockClient: ApiClient;
  let service: IAMService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
    service = new IAMService(mockClient);
  });

  it('POSTs /v1/iam/tenants/{tenant}/apps/{id}/rotate', async () => {
    await service.rotateAppSecret('t1', 'c1');
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/iam/tenants/t1/apps/c1/rotate', {});
  });

  it('encodes the tenant path segment', async () => {
    await service.rotateAppSecret('t/1', 'c1');
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/iam/tenants/t%2F1/apps/c1/rotate', {});
  });
});
