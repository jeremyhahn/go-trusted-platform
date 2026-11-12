/**
 * EABService route tests for the mark-used and cleanup operations (#1667).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EABService } from '../eab-service.js';
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

describe('EABService', () => {
  let mockClient: ApiClient;
  let service: EABService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new EABService(mockClient);
  });

  describe('markUsed', () => {
    it('posts to /credentials/{id}/used', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({
        success: true,
        data: { status: { success: true, message: 'ok' } },
      });

      const res = await service.markUsed(42);

      expect(mockClient.post).toHaveBeenCalledTimes(1);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/eab/credentials/42/used', {});
      expect(res.data?.status.success).toBe(true);
    });

    it('propagates a transport failure', async () => {
      const failure = new Error('boom');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.markUsed(7)).rejects.toBe(failure);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/eab/credentials/7/used', {});
    });
  });

  describe('cleanupExpired', () => {
    it('posts an empty body to /credentials/cleanup without a tenant', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({
        success: true,
        data: { deletedCount: 3, status: { success: true, message: 'ok' } },
      });

      const res = await service.cleanupExpired();

      expect(mockClient.post).toHaveBeenCalledTimes(1);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/eab/credentials/cleanup', {});
      expect(res.data?.deletedCount).toBe(3);
    });

    it('passes the tenant filter in the body', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({
        success: true,
        data: { deletedCount: 0, status: { success: true, message: 'ok' } },
      });

      await service.cleanupExpired({ tenantId: 'tenant-a' });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/eab/credentials/cleanup', {
        tenantId: 'tenant-a',
      });
    });
  });
});
