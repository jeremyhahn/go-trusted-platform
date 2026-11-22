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

      const res = await service.markUsed('42');

      expect(mockClient.post).toHaveBeenCalledTimes(1);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/eab/credentials/42/used', {});
      expect(res.data?.status.success).toBe(true);
    });

    it('propagates a transport failure', async () => {
      const failure = new Error('boom');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.markUsed('7')).rejects.toBe(failure);
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

  describe('getEnrollmentURL', () => {
    it('gets the registered /credentials/{id}/url route', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({
        success: true,
        data: { url: '/enroll?kid=kid-5', timestamp: '2026-01-01T00:00:00Z' },
      });

      const res = await service.getEnrollmentURL('5');

      expect(mockClient.get).toHaveBeenCalledTimes(1);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/eab/credentials/5/url');
      expect(res.data?.url).toBe('/enroll?kid=kid-5');
    });

    it('passes the wire url and generation timestamp through, with no expiry', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({
        success: true,
        data: { url: '/enroll?kid=kid-7', timestamp: '2026-02-03T04:05:06Z' },
      });

      const res = await service.getEnrollmentURL('7');

      expect(res.success).toBe(true);
      expect(res.data).toEqual({ url: '/enroll?kid=kid-7', timestamp: '2026-02-03T04:05:06Z' });
      expect(Object.keys(res.data ?? {}).sort()).toEqual(['timestamp', 'url']);
      // The response type carries the generation time, not an expiry.
      const data: { url: string; timestamp: string } | undefined = res.data;
      expect(data?.timestamp).toBe('2026-02-03T04:05:06Z');
    });
  });

  describe('uint64 ids', () => {
    it('keeps a uint64 id above MAX_SAFE_INTEGER in the path', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

      await service.get('1762905600123456789');

      expect(mockClient.get).toHaveBeenCalledTimes(1);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/eab/credentials/1762905600123456789');
    });
  });

  describe('credential id validation (#2022 Codex r1)', () => {
    it('rejects an id that would reach another route, without a transport call', async () => {
      await expect(service.markUsed('cleanup?')).rejects.toThrow(RangeError);
      expect(mockClient.post).not.toHaveBeenCalled();
    });

    it('rejects an id with a path separator, without a transport call', async () => {
      await expect(service.getEnrollmentURL('1/2')).rejects.toThrow(RangeError);
      expect(mockClient.get).not.toHaveBeenCalled();
    });

    it('rejects an empty id in every id method, without a transport call', async () => {
      await expect(service.get('')).rejects.toThrow(RangeError);
      await expect(service.revoke('')).rejects.toThrow(RangeError);
      await expect(service.delete('')).rejects.toThrow(RangeError);
      await expect(service.getQRCode('')).rejects.toThrow(RangeError);
      await expect(service.getEnrollmentURL('')).rejects.toThrow(RangeError);
      await expect(service.markUsed('')).rejects.toThrow(RangeError);
      expect(mockClient.get).not.toHaveBeenCalled();
      expect(mockClient.post).not.toHaveBeenCalled();
      expect(mockClient.delete).not.toHaveBeenCalled();
    });

    it('posts the max uint64 id to its used route', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

      await service.markUsed('18446744073709551615');

      expect(mockClient.post).toHaveBeenCalledWith(
        '/v1/eab/credentials/18446744073709551615/used',
        {}
      );
    });
  });
});
