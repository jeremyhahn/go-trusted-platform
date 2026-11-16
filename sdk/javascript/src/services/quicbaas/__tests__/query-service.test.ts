/**
 * Unit tests for QueryService
 *
 * Tests secondary index queries for efficient data retrieval by field values.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QueryService } from '../query-service.js';
import type { ApiClient } from '../../../client/api-client.js';
import type { ApiResponse } from '../../../types/api.js';
import type { QueryOperator } from '../../../types/quicbaas/core-data.js';

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

describe('QueryService', () => {
  let service: QueryService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new QueryService(mockClient);
  });

  // =========================================================================
  // query() tests
  // =========================================================================

  describe('query', () => {
    it('should execute a basic query', async () => {
      const mockResponse: ApiResponse<{
        items: Array<{ key: string; value: string }>;
        totalCount: number;
      }> = {
        success: true,
        data: {
          items: [
            { key: 'users/user-1', value: '{"name":"John"}' },
            { key: 'users/user-2', value: '{"name":"Jane"}' },
          ],
          totalCount: 2,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.query({
        prefix: 'users/',
      });

      expect(result.success).toBe(true);
      expect(result.data?.items).toHaveLength(2);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/query', {
        prefix: 'users/',
        filters: undefined,
        sorts: undefined,
        projection: undefined,
        limit: undefined,
        offset: undefined,
        cursor: undefined,
        consistency: undefined,
      });
    });

    it('should query with filters', async () => {
      const mockResponse: ApiResponse<{ items: unknown[]; totalCount: number }> = {
        success: true,
        data: { items: [], totalCount: 0 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.query({
        prefix: 'users/',
        filters: [
          { field: 'status', operator: 'EQ', value: 'active' },
          { field: 'createdAt', operator: 'GTE', value: 1704067200000 },
        ],
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/query', {
        prefix: 'users/',
        filters: [
          { field: 'status', operator: 'EQ', value: 'active' },
          { field: 'createdAt', operator: 'GTE', value: 1704067200000 },
        ],
        sorts: undefined,
        projection: undefined,
        limit: undefined,
        offset: undefined,
        cursor: undefined,
        consistency: undefined,
      });
    });

    it('should query with sorting', async () => {
      const mockResponse: ApiResponse<{ items: unknown[]; totalCount: number }> = {
        success: true,
        data: { items: [], totalCount: 0 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.query({
        prefix: 'users/',
        sorts: [{ field: 'createdAt', order: 'DESC' }],
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/query', {
        prefix: 'users/',
        filters: undefined,
        sorts: [{ field: 'createdAt', order: 'DESC' }],
        projection: undefined,
        limit: undefined,
        offset: undefined,
        cursor: undefined,
        consistency: undefined,
      });
    });

    it('should query with projection', async () => {
      const mockResponse: ApiResponse<{ items: unknown[]; totalCount: number }> = {
        success: true,
        data: { items: [], totalCount: 0 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.query({
        prefix: 'users/',
        projection: { include: ['name', 'email'] },
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/query', {
        prefix: 'users/',
        filters: undefined,
        sorts: undefined,
        projection: { include: ['name', 'email'] },
        limit: undefined,
        offset: undefined,
        cursor: undefined,
        consistency: undefined,
      });
    });

    it('should query with pagination using limit and offset', async () => {
      const mockResponse: ApiResponse<{ items: unknown[]; totalCount: number }> = {
        success: true,
        data: { items: [], totalCount: 100 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.query({
        prefix: 'users/',
        limit: 10,
        offset: 20,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/query', {
        prefix: 'users/',
        filters: undefined,
        sorts: undefined,
        projection: undefined,
        limit: 10,
        offset: 20,
        cursor: undefined,
        consistency: undefined,
      });
    });

    it('should query with cursor pagination', async () => {
      const mockResponse: ApiResponse<{
        items: unknown[];
        totalCount: number;
        cursor?: string;
      }> = {
        success: true,
        data: { items: [], totalCount: 100, cursor: 'next-page' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.query({
        prefix: 'users/',
        cursor: 'current-page',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/query', {
        prefix: 'users/',
        filters: undefined,
        sorts: undefined,
        projection: undefined,
        limit: undefined,
        offset: undefined,
        cursor: 'current-page',
        consistency: undefined,
      });
    });

    it('should query with consistency level', async () => {
      const mockResponse: ApiResponse<{ items: unknown[]; totalCount: number }> = {
        success: true,
        data: { items: [], totalCount: 0 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.query({
        prefix: 'users/',
        consistency: 'STRONG',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/query', {
        prefix: 'users/',
        filters: undefined,
        sorts: undefined,
        projection: undefined,
        limit: undefined,
        offset: undefined,
        cursor: undefined,
        consistency: 'STRONG',
      });
    });

    it('should handle query error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INVALID_QUERY', message: 'Invalid filter expression' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.query({
        prefix: 'users/',
        filters: [{ field: 'invalid', operator: 'BAD' as QueryOperator, value: 'x' }],
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INVALID_QUERY');
    });
  });

  // =========================================================================
  // createIndex() tests
  // =========================================================================

  describe('createIndex', () => {
    it('should create a basic index', async () => {
      const mockResponse: ApiResponse<{
        name: string;
        state: string;
        createdAt: number;
      }> = {
        success: true,
        data: {
          name: 'users_by_email',
          state: 'BUILDING',
          createdAt: Date.now(),
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.createIndex({
        name: 'users_by_email',
        prefix: 'users/',
        type: 'BTREE',
        fields: [{ field: 'email', order: 'ASC' }],
      });

      expect(result.success).toBe(true);
      expect(result.data).toMatchObject({ name: 'users_by_email' });
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/indexes', {
        name: 'users_by_email',
        prefix: 'users/',
        type: 'BTREE',
        fields: [{ field: 'email', order: 'ASC' }],
        background: undefined,
        unique: undefined,
        sparse: undefined,
      });
    });

    it('should create a unique index', async () => {
      const mockResponse: ApiResponse<{ name: string; state: string }> = {
        success: true,
        data: { name: 'users_email_unique', state: 'BUILDING' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.createIndex({
        name: 'users_email_unique',
        prefix: 'users/',
        type: 'BTREE',
        fields: [{ field: 'email', order: 'ASC' }],
        unique: true,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/indexes', {
        name: 'users_email_unique',
        prefix: 'users/',
        type: 'BTREE',
        fields: [{ field: 'email', order: 'ASC' }],
        background: undefined,
        unique: true,
        sparse: undefined,
      });
    });

    it('should create a sparse index', async () => {
      const mockResponse: ApiResponse<{ name: string; state: string }> = {
        success: true,
        data: { name: 'users_phone_sparse', state: 'BUILDING' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.createIndex({
        name: 'users_phone_sparse',
        prefix: 'users/',
        type: 'BTREE',
        fields: [{ field: 'phone', order: 'ASC' }],
        sparse: true,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/indexes', {
        name: 'users_phone_sparse',
        prefix: 'users/',
        type: 'BTREE',
        fields: [{ field: 'phone', order: 'ASC' }],
        background: undefined,
        unique: undefined,
        sparse: true,
      });
    });

    it('should create index in background', async () => {
      const mockResponse: ApiResponse<{ name: string; state: string }> = {
        success: true,
        data: { name: 'large_index', state: 'BUILDING' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.createIndex({
        name: 'large_index',
        prefix: 'data/',
        type: 'BTREE',
        fields: [{ field: 'timestamp', order: 'DESC' }],
        background: true,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/indexes', {
        name: 'large_index',
        prefix: 'data/',
        type: 'BTREE',
        fields: [{ field: 'timestamp', order: 'DESC' }],
        background: true,
        unique: undefined,
        sparse: undefined,
      });
    });

    it('should create compound index', async () => {
      const mockResponse: ApiResponse<{ name: string; state: string }> = {
        success: true,
        data: { name: 'compound_index', state: 'BUILDING' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.createIndex({
        name: 'compound_index',
        prefix: 'orders/',
        type: 'BTREE',
        fields: [
          { field: 'customerId', order: 'ASC' },
          { field: 'createdAt', order: 'DESC' },
        ],
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/indexes', {
        name: 'compound_index',
        prefix: 'orders/',
        type: 'BTREE',
        fields: [
          { field: 'customerId', order: 'ASC' },
          { field: 'createdAt', order: 'DESC' },
        ],
        background: undefined,
        unique: undefined,
        sparse: undefined,
      });
    });

    it('should handle index already exists error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'ALREADY_EXISTS', message: 'Index already exists' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.createIndex({
        name: 'existing_index',
        prefix: 'users/',
        type: 'BTREE',
        fields: [{ field: 'email', order: 'ASC' }],
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('ALREADY_EXISTS');
    });
  });

  // =========================================================================
  // deleteIndex() tests
  // =========================================================================

  describe('deleteIndex', () => {
    it('should delete an index', async () => {
      const mockResponse: ApiResponse<{ deleted: boolean }> = {
        success: true,
        data: { deleted: true },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      const result = await service.deleteIndex({
        name: 'users_by_email',
      });

      expect(result.success).toBe(true);
      expect(result.data).toMatchObject({ deleted: true });
      expect(mockClient.delete).toHaveBeenCalledWith('/v1/quicbaas/indexes/users_by_email');
    });

    it('should encode special characters in index name', async () => {
      const mockResponse: ApiResponse<{ deleted: boolean }> = {
        success: true,
        data: { deleted: true },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      await service.deleteIndex({
        name: 'index/with/slashes',
      });

      expect(mockClient.delete).toHaveBeenCalledWith('/v1/quicbaas/indexes/index%2Fwith%2Fslashes');
    });

    it('should handle index not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Index not found' },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      const result = await service.deleteIndex({
        name: 'nonexistent',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });
  });

  // =========================================================================
  // listIndexes() tests
  // =========================================================================

  describe('listIndexes', () => {
    it('should list all indexes', async () => {
      const mockResponse: ApiResponse<{
        indexes: Array<{
          name: string;
          prefix: string;
          type: string;
          state: string;
          entryCount: number;
        }>;
      }> = {
        success: true,
        data: {
          indexes: [
            {
              name: 'users_by_email',
              prefix: 'users/',
              type: 'BTREE',
              state: 'READY',
              entryCount: 1000,
            },
            {
              name: 'orders_by_date',
              prefix: 'orders/',
              type: 'BTREE',
              state: 'READY',
              entryCount: 5000,
            },
          ],
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.listIndexes();

      expect(result.success).toBe(true);
      expect(result.data?.indexes).toHaveLength(2);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/quicbaas/indexes');
    });

    it('should list indexes with prefix filter', async () => {
      const mockResponse: ApiResponse<{ indexes: unknown[] }> = {
        success: true,
        data: { indexes: [] },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.listIndexes({ prefix: 'users/' });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('prefix=users%2F')
      );
    });

    it('should list indexes with pagination', async () => {
      const mockResponse: ApiResponse<{
        indexes: unknown[];
        cursor?: string;
      }> = {
        success: true,
        data: { indexes: [], cursor: 'next-cursor' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.listIndexes({ limit: 10, cursor: 'current-cursor' });

      const call = vi.mocked(mockClient.get).mock.calls[0]?.[0];
      expect(call).toContain('limit=10');
      expect(call).toContain('cursor=current-cursor');
    });

    it('should handle list indexes error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INTERNAL_ERROR', message: 'Failed to list indexes' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.listIndexes();

      expect(result.success).toBe(false);
    });
  });
});
