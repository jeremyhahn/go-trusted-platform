/**
 * Unit tests for KVService
 *
 * Tests all key-value CRUD operations with watch support.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { KVService } from '../kv-service.js';
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

describe('KVService', () => {
  let service: KVService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new KVService(mockClient);
  });

  // =========================================================================
  // get() tests
  // =========================================================================

  describe('get', () => {
    it('should get a value by key', async () => {
      const mockResponse: ApiResponse<{ key: string; value: string; version: number }> = {
        success: true,
        data: {
          key: 'users/user-123',
          value: 'dGVzdC1kYXRh',
          version: 1,
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.get({ key: 'users/user-123' });

      expect(result.success).toBe(true);
      expect(result.data).toMatchObject({ key: 'users/user-123' });
      expect(mockClient.get).toHaveBeenCalledWith('/v1/quicbaas/kv/users%2Fuser-123');
    });

    it('should include consistency parameter when specified', async () => {
      const mockResponse: ApiResponse<{ key: string; value: string }> = {
        success: true,
        data: { key: 'test', value: 'data' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.get({ key: 'test', consistency: 'STRONG' });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('consistency=STRONG')
      );
    });

    it('should include version parameter when specified', async () => {
      const mockResponse: ApiResponse<{ key: string; value: string }> = {
        success: true,
        data: { key: 'test', value: 'data' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.get({ key: 'test', version: 5 });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('version=5')
      );
    });

    it('should handle not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Key not found' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.get({ key: 'nonexistent' });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });

    it('should encode special characters in key', async () => {
      const mockResponse: ApiResponse<{ key: string; value: string }> = {
        success: true,
        data: { key: 'path/with spaces/key', value: 'data' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.get({ key: 'path/with spaces/key' });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('path%2Fwith%20spaces%2Fkey')
      );
    });
  });

  // =========================================================================
  // put() tests
  // =========================================================================

  describe('put', () => {
    it('should put a value', async () => {
      const mockResponse: ApiResponse<{ version: number }> = {
        success: true,
        data: { version: 1 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.put({
        key: 'users/user-123',
        value: 'dGVzdC1kYXRh',
      });

      expect(result.success).toBe(true);
      expect(result.data?.version).toBe(1);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/kv', {
        key: 'users/user-123',
        value: 'dGVzdC1kYXRh',
        ttl: undefined,
        metadata: undefined,
        ifNotExists: undefined,
        ifVersion: undefined,
      });
    });

    it('should put a value with TTL', async () => {
      const mockResponse: ApiResponse<{ version: number }> = {
        success: true,
        data: { version: 1 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.put({
        key: 'temp/data',
        value: 'data',
        ttl: 3600,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/kv', {
        key: 'temp/data',
        value: 'data',
        ttl: 3600,
        metadata: undefined,
        ifNotExists: undefined,
        ifVersion: undefined,
      });
    });

    it('should put a value with metadata', async () => {
      const mockResponse: ApiResponse<{ version: number }> = {
        success: true,
        data: { version: 1 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.put({
        key: 'users/user-123',
        value: 'data',
        metadata: { contentType: 'application/json' },
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/kv', {
        key: 'users/user-123',
        value: 'data',
        ttl: undefined,
        metadata: { contentType: 'application/json' },
        ifNotExists: undefined,
        ifVersion: undefined,
      });
    });

    it('should put with ifNotExists condition', async () => {
      const mockResponse: ApiResponse<{ version: number }> = {
        success: true,
        data: { version: 1 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.put({
        key: 'unique/key',
        value: 'data',
        ifNotExists: true,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/kv', {
        key: 'unique/key',
        value: 'data',
        ttl: undefined,
        metadata: undefined,
        ifNotExists: true,
        ifVersion: undefined,
      });
    });

    it('should put with ifVersion condition', async () => {
      const mockResponse: ApiResponse<{ version: number }> = {
        success: true,
        data: { version: 2 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.put({
        key: 'users/user-123',
        value: 'updated-data',
        ifVersion: 1,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/kv', {
        key: 'users/user-123',
        value: 'updated-data',
        ttl: undefined,
        metadata: undefined,
        ifNotExists: undefined,
        ifVersion: 1,
      });
    });

    it('should handle conflict error on conditional put', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'CONFLICT', message: 'Version mismatch' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.put({
        key: 'users/user-123',
        value: 'data',
        ifVersion: 5,
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('CONFLICT');
    });
  });

  // =========================================================================
  // delete() tests
  // =========================================================================

  describe('delete', () => {
    it('should delete a value by key', async () => {
      const mockResponse: ApiResponse<{ deleted: boolean; previousValue?: string }> = {
        success: true,
        data: { deleted: true, previousValue: 'old-data' },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      const result = await service.delete({ key: 'users/user-123' });

      expect(result.success).toBe(true);
      expect(result.data?.deleted).toBe(true);
      expect(mockClient.delete).toHaveBeenCalledWith('/v1/quicbaas/kv/users%2Fuser-123');
    });

    it('should delete with ifVersion condition', async () => {
      const mockResponse: ApiResponse<{ deleted: boolean }> = {
        success: true,
        data: { deleted: true },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      await service.delete({ key: 'users/user-123', ifVersion: 5 });

      expect(mockClient.delete).toHaveBeenCalledWith(
        expect.stringContaining('ifVersion=5')
      );
    });

    it('should handle not found on delete', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Key not found' },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      const result = await service.delete({ key: 'nonexistent' });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });
  });

  // =========================================================================
  // list() tests
  // =========================================================================

  describe('list', () => {
    it('should list all keys without filters', async () => {
      const mockResponse: ApiResponse<{ items: Array<{ key: string }>; cursor?: string }> = {
        success: true,
        data: {
          items: [{ key: 'users/user-1' }, { key: 'users/user-2' }],
          cursor: 'next-cursor',
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.list();

      expect(result.success).toBe(true);
      expect(result.data).toHaveProperty(['items', 'length'], 2);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/quicbaas/kv');
    });

    it('should list keys with prefix filter', async () => {
      const mockResponse: ApiResponse<{ items: Array<{ key: string }> }> = {
        success: true,
        data: { items: [{ key: 'users/user-1' }] },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.list({ prefix: 'users/' });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('prefix=users%2F')
      );
    });

    it('should list keys with range filters', async () => {
      const mockResponse: ApiResponse<{ items: Array<{ key: string }> }> = {
        success: true,
        data: { items: [] },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.list({ startKey: 'a', endKey: 'z' });

      const call = vi.mocked(mockClient.get).mock.calls[0]?.[0];
      expect(call).toContain('startKey=a');
      expect(call).toContain('endKey=z');
    });

    it('should list keys with pagination', async () => {
      const mockResponse: ApiResponse<{ items: Array<{ key: string }> }> = {
        success: true,
        data: { items: [] },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.list({ limit: 100, cursor: 'page-2' });

      const call = vi.mocked(mockClient.get).mock.calls[0]?.[0];
      expect(call).toContain('limit=100');
      expect(call).toContain('cursor=page-2');
    });

    it('should list with includeValues option', async () => {
      const mockResponse: ApiResponse<{ items: Array<{ key: string; value: string }> }> = {
        success: true,
        data: { items: [{ key: 'k1', value: 'v1' }] },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.list({ includeValues: true });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('includeValues=true')
      );
    });

    it('should list with consistency option', async () => {
      const mockResponse: ApiResponse<{ items: Array<{ key: string }> }> = {
        success: true,
        data: { items: [] },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.list({ consistency: 'STRONG' });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('consistency=STRONG')
      );
    });
  });

  // =========================================================================
  // watch() tests
  // =========================================================================

  describe('watch', () => {
    it('should create a watch on a key', async () => {
      const mockResponse: ApiResponse<{ watchId: string; events: unknown[] }> = {
        success: true,
        data: { watchId: 'watch-123', events: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.watch({ key: 'users/user-123' });

      expect(result.success).toBe(true);
      expect(result.data?.watchId).toBe('watch-123');
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/kv/watch', {
        key: 'users/user-123',
        prefix: undefined,
        startRevision: undefined,
        eventTypes: undefined,
      });
    });

    it('should create a watch on a prefix', async () => {
      const mockResponse: ApiResponse<{ watchId: string; events: unknown[] }> = {
        success: true,
        data: { watchId: 'watch-456', events: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.watch({ prefix: 'users/' });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/kv/watch', {
        key: undefined,
        prefix: 'users/',
        startRevision: undefined,
        eventTypes: undefined,
      });
    });

    it('should watch with event type filter', async () => {
      const mockResponse: ApiResponse<{ watchId: string; events: unknown[] }> = {
        success: true,
        data: { watchId: 'watch-789', events: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.watch({
        prefix: 'users/',
        eventTypes: ['PUT', 'DELETE'],
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/kv/watch', {
        key: undefined,
        prefix: 'users/',
        startRevision: undefined,
        eventTypes: ['PUT', 'DELETE'],
      });
    });

    it('should watch from specific revision', async () => {
      const mockResponse: ApiResponse<{ watchId: string; events: unknown[] }> = {
        success: true,
        data: { watchId: 'watch-abc', events: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.watch({ key: 'config/app', startRevision: 100 });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/kv/watch', {
        key: 'config/app',
        prefix: undefined,
        startRevision: 100,
        eventTypes: undefined,
      });
    });

    it('should handle watch creation error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'WATCH_LIMIT_EXCEEDED', message: 'Too many watches' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.watch({ key: 'test' });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('WATCH_LIMIT_EXCEEDED');
    });
  });
});
