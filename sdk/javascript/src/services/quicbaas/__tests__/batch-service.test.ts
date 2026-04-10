/**
 * Unit tests for BatchService
 *
 * Tests atomic batch operations for efficient bulk read/write operations.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BatchService } from '../batch-service.js';
import type { ApiClient } from '../../../client/api-client.js';
import type { ApiResponse } from '../../../types/api.js';

// Mock ApiClient
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
    interceptors: {
      request: { add: vi.fn(), getAll: vi.fn(() => []) },
      response: { add: vi.fn(), getAll: vi.fn(() => []) },
      error: { add: vi.fn(), getAll: vi.fn(() => []) },
    },
    addRequestInterceptor: vi.fn(),
    addResponseInterceptor: vi.fn(),
    addErrorInterceptor: vi.fn(),
  } as unknown as ApiClient;
}

describe('BatchService', () => {
  let service: BatchService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new BatchService(mockClient);
  });

  // =========================================================================
  // batchGet() tests
  // =========================================================================

  describe('batchGet', () => {
    it('should get multiple keys in batch', async () => {
      const mockResponse: ApiResponse<{
        items: Array<{ key: string; value: string; version: number } | null>;
      }> = {
        success: true,
        data: {
          items: [
            { key: 'users/user-1', value: 'data1', version: 1 },
            { key: 'users/user-2', value: 'data2', version: 1 },
            null, // key not found
          ],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.batchGet({
        keys: ['users/user-1', 'users/user-2', 'users/user-3'],
      });

      expect(result.success).toBe(true);
      expect(result.data?.items).toHaveLength(3);
      expect(result.data?.items[2]).toBeNull();
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/batch/get', {
        keys: ['users/user-1', 'users/user-2', 'users/user-3'],
        consistency: undefined,
      });
    });

    it('should batch get with strong consistency', async () => {
      const mockResponse: ApiResponse<{
        items: Array<{ key: string; value: string } | null>;
      }> = {
        success: true,
        data: { items: [{ key: 'k1', value: 'v1' }] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.batchGet({
        keys: ['k1'],
        consistency: 'STRONG',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/batch/get', {
        keys: ['k1'],
        consistency: 'STRONG',
      });
    });

    it('should batch get with eventual consistency', async () => {
      const mockResponse: ApiResponse<{
        items: Array<{ key: string; value: string } | null>;
      }> = {
        success: true,
        data: { items: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.batchGet({
        keys: ['k1', 'k2'],
        consistency: 'EVENTUAL',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/batch/get', {
        keys: ['k1', 'k2'],
        consistency: 'EVENTUAL',
      });
    });

    it('should handle empty keys array', async () => {
      const mockResponse: ApiResponse<{ items: unknown[] }> = {
        success: true,
        data: { items: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.batchGet({ keys: [] });

      expect(result.success).toBe(true);
      expect(result.data?.items).toHaveLength(0);
    });

    it('should handle batch get error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'BATCH_TOO_LARGE', message: 'Too many keys in batch' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.batchGet({
        keys: Array(10000).fill('key'),
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('BATCH_TOO_LARGE');
    });
  });

  // =========================================================================
  // batchPut() tests
  // =========================================================================

  describe('batchPut', () => {
    it('should put multiple items in batch', async () => {
      const mockResponse: ApiResponse<{
        results: Array<{ key: string; version: number; success: boolean }>;
      }> = {
        success: true,
        data: {
          results: [
            { key: 'config/setting-1', version: 1, success: true },
            { key: 'config/setting-2', version: 1, success: true },
          ],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.batchPut({
        items: [
          { key: 'config/setting-1', value: 'value1' },
          { key: 'config/setting-2', value: 'value2' },
        ],
      });

      expect(result.success).toBe(true);
      expect(result.data?.results).toHaveLength(2);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/batch/put', {
        items: [
          { key: 'config/setting-1', value: 'value1' },
          { key: 'config/setting-2', value: 'value2' },
        ],
        atomic: undefined,
      });
    });

    it('should batch put with TTL', async () => {
      const mockResponse: ApiResponse<{
        results: Array<{ key: string; version: number; success: boolean }>;
      }> = {
        success: true,
        data: {
          results: [{ key: 'temp/data', version: 1, success: true }],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.batchPut({
        items: [{ key: 'temp/data', value: 'data', ttl: 3600 }],
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/batch/put', {
        items: [{ key: 'temp/data', value: 'data', ttl: 3600 }],
        atomic: undefined,
      });
    });

    it('should batch put with atomic mode', async () => {
      const mockResponse: ApiResponse<{
        results: Array<{ key: string; version: number; success: boolean }>;
      }> = {
        success: true,
        data: {
          results: [
            { key: 'k1', version: 1, success: true },
            { key: 'k2', version: 1, success: true },
          ],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.batchPut({
        items: [
          { key: 'k1', value: 'v1' },
          { key: 'k2', value: 'v2' },
        ],
        atomic: true,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/batch/put', {
        items: [
          { key: 'k1', value: 'v1' },
          { key: 'k2', value: 'v2' },
        ],
        atomic: true,
      });
    });

    it('should batch put with non-atomic mode', async () => {
      const mockResponse: ApiResponse<{
        results: Array<{ key: string; version: number; success: boolean }>;
      }> = {
        success: true,
        data: { results: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.batchPut({
        items: [{ key: 'k1', value: 'v1' }],
        atomic: false,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/batch/put', {
        items: [{ key: 'k1', value: 'v1' }],
        atomic: false,
      });
    });

    it('should handle partial failure in non-atomic mode', async () => {
      const mockResponse: ApiResponse<{
        results: Array<{ key: string; success: boolean; error?: string }>;
      }> = {
        success: true,
        data: {
          results: [
            { key: 'k1', success: true },
            { key: 'k2', success: false, error: 'Key already exists' },
          ],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.batchPut({
        items: [
          { key: 'k1', value: 'v1' },
          { key: 'k2', value: 'v2' },
        ],
        atomic: false,
      });

      expect(result.success).toBe(true);
      expect(result.data?.results[0].success).toBe(true);
      expect(result.data?.results[1].success).toBe(false);
    });

    it('should handle atomic batch put failure', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'TRANSACTION_FAILED', message: 'Atomic batch failed' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.batchPut({
        items: [
          { key: 'k1', value: 'v1' },
          { key: 'k2', value: 'v2' },
        ],
        atomic: true,
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('TRANSACTION_FAILED');
    });
  });

  // =========================================================================
  // batchDelete() tests
  // =========================================================================

  describe('batchDelete', () => {
    it('should delete multiple keys in batch', async () => {
      const mockResponse: ApiResponse<{
        results: Array<{ key: string; success: boolean; existed: boolean }>;
      }> = {
        success: true,
        data: {
          results: [
            { key: 'temp/file-1', success: true, existed: true },
            { key: 'temp/file-2', success: true, existed: true },
          ],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.batchDelete({
        keys: ['temp/file-1', 'temp/file-2'],
      });

      expect(result.success).toBe(true);
      expect(result.data?.results).toHaveLength(2);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/batch/delete', {
        keys: ['temp/file-1', 'temp/file-2'],
        atomic: undefined,
      });
    });

    it('should batch delete with atomic mode', async () => {
      const mockResponse: ApiResponse<{
        results: Array<{ key: string; success: boolean }>;
      }> = {
        success: true,
        data: {
          results: [
            { key: 'k1', success: true },
            { key: 'k2', success: true },
          ],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.batchDelete({
        keys: ['k1', 'k2'],
        atomic: true,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/batch/delete', {
        keys: ['k1', 'k2'],
        atomic: true,
      });
    });

    it('should batch delete with non-atomic mode', async () => {
      const mockResponse: ApiResponse<{
        results: Array<{ key: string; success: boolean }>;
      }> = {
        success: true,
        data: { results: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.batchDelete({
        keys: ['k1'],
        atomic: false,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/batch/delete', {
        keys: ['k1'],
        atomic: false,
      });
    });

    it('should handle non-existent keys in batch delete', async () => {
      const mockResponse: ApiResponse<{
        results: Array<{ key: string; success: boolean; existed: boolean }>;
      }> = {
        success: true,
        data: {
          results: [
            { key: 'exists', success: true, existed: true },
            { key: 'not-exists', success: true, existed: false },
          ],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.batchDelete({
        keys: ['exists', 'not-exists'],
      });

      expect(result.success).toBe(true);
      expect(result.data?.results[0].existed).toBe(true);
      expect(result.data?.results[1].existed).toBe(false);
    });

    it('should handle batch delete error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'PERMISSION_DENIED', message: 'Cannot delete protected keys' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.batchDelete({
        keys: ['protected/key'],
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('PERMISSION_DENIED');
    });
  });
});
