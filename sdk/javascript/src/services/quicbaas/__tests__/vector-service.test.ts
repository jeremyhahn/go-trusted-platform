/**
 * Unit tests for VectorService
 *
 * Tests vector similarity search operations including k-NN search,
 * namespace management, and index statistics.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VectorService } from '../vector-service.js';
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

describe('VectorService', () => {
  let service: VectorService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new VectorService(mockClient);
  });

  // =========================================================================
  // insert() tests
  // =========================================================================

  describe('insert', () => {
    it('should insert vectors into a namespace', async () => {
      const mockResponse: ApiResponse<{ insertedCount: number; insertedIds: string[] }> = {
        success: true,
        data: { insertedCount: 2, insertedIds: ['vec-1', 'vec-2'] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.insert({
        namespace: 'documents',
        vectors: [
          { id: 'vec-1', values: [0.1, 0.2, 0.3] },
          { id: 'vec-2', values: [0.4, 0.5, 0.6] },
        ],
      });

      expect(result.success).toBe(true);
      expect(result.data?.insertedCount).toBe(2);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/vector/insert', {
        namespace: 'documents',
        vectors: [
          { id: 'vec-1', values: [0.1, 0.2, 0.3] },
          { id: 'vec-2', values: [0.4, 0.5, 0.6] },
        ],
      });
    });

    it('should insert vectors with metadata', async () => {
      const mockResponse: ApiResponse<{ insertedCount: number; insertedIds: string[] }> = {
        success: true,
        data: { insertedCount: 1, insertedIds: ['vec-1'] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.insert({
        namespace: 'documents',
        vectors: [
          {
            id: 'vec-1',
            values: [0.1, 0.2, 0.3],
            metadata: { title: 'Document 1', category: 'tech' },
          },
        ],
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/vector/insert', {
        namespace: 'documents',
        vectors: [
          {
            id: 'vec-1',
            values: [0.1, 0.2, 0.3],
            metadata: { title: 'Document 1', category: 'tech' },
          },
        ],
      });
    });

    it('should insert with overwrite option', async () => {
      const mockResponse: ApiResponse<{ insertedCount: number; insertedIds: string[] }> = {
        success: true,
        data: { insertedCount: 1, insertedIds: ['vec-1'] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.insert({
        namespace: 'documents',
        vectors: [{ id: 'vec-1', values: [0.1, 0.2, 0.3] }],
        overwrite: true,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/vector/insert', {
        namespace: 'documents',
        vectors: [{ id: 'vec-1', values: [0.1, 0.2, 0.3] }],
        overwrite: true,
      });
    });

    it('should handle dimension mismatch error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'DIMENSION_MISMATCH', message: 'Vector dimension does not match namespace' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.insert({
        namespace: 'documents',
        vectors: [{ id: 'vec-1', values: [0.1, 0.2] }],
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('DIMENSION_MISMATCH');
    });
  });

  // =========================================================================
  // search() tests
  // =========================================================================

  describe('search', () => {
    it('should search for similar vectors', async () => {
      const mockResponse: ApiResponse<{ results: Array<{ id: string; score: number }> }> = {
        success: true,
        data: {
          results: [
            { id: 'vec-1', score: 0.95 },
            { id: 'vec-2', score: 0.87 },
          ],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.search({
        namespace: 'documents',
        vector: [0.1, 0.2, 0.3],
        topK: 10,
      });

      expect(result.success).toBe(true);
      expect(result.data?.results).toHaveLength(2);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/vector/search', {
        namespace: 'documents',
        vector: [0.1, 0.2, 0.3],
        topK: 10,
      });
    });

    it('should search with score threshold', async () => {
      const mockResponse: ApiResponse<{ results: Array<{ id: string; score: number }> }> = {
        success: true,
        data: { results: [{ id: 'vec-1', score: 0.95 }] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.search({
        namespace: 'documents',
        vector: [0.1, 0.2, 0.3],
        topK: 10,
        scoreThreshold: 0.9,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/vector/search', {
        namespace: 'documents',
        vector: [0.1, 0.2, 0.3],
        topK: 10,
        scoreThreshold: 0.9,
      });
    });

    it('should search with metadata filter', async () => {
      const mockResponse: ApiResponse<{ results: Array<{ id: string; score: number }> }> = {
        success: true,
        data: { results: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.search({
        namespace: 'documents',
        vector: [0.1, 0.2, 0.3],
        topK: 5,
        filter: { category: 'tech' },
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/vector/search', {
        namespace: 'documents',
        vector: [0.1, 0.2, 0.3],
        topK: 5,
        filter: { category: 'tech' },
      });
    });

    it('should search with includeMetadata option', async () => {
      const mockResponse: ApiResponse<{
        results: Array<{ id: string; score: number; metadata?: Record<string, unknown> }>;
      }> = {
        success: true,
        data: {
          results: [{ id: 'vec-1', score: 0.95, metadata: { title: 'Doc 1' } }],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.search({
        namespace: 'documents',
        vector: [0.1, 0.2, 0.3],
        topK: 10,
        includeMetadata: true,
      });

      expect(result.data?.results[0]?.metadata).toBeDefined();
    });

    it('should handle namespace not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Namespace not found' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.search({
        namespace: 'nonexistent',
        vector: [0.1, 0.2, 0.3],
        topK: 10,
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });
  });

  // =========================================================================
  // searchSimilar() tests
  // =========================================================================

  describe('searchSimilar', () => {
    it('should search by existing vector ID', async () => {
      const mockResponse: ApiResponse<{ results: Array<{ id: string; score: number }> }> = {
        success: true,
        data: {
          results: [
            { id: 'vec-2', score: 0.92 },
            { id: 'vec-3', score: 0.88 },
          ],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.searchSimilar({
        namespace: 'documents',
        id: 'vec-1',
        topK: 5,
      });

      expect(result.success).toBe(true);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/vector/search/similar', {
        namespace: 'documents',
        id: 'vec-1',
        topK: 5,
      });
    });

    it('should search similar with includeMetadata', async () => {
      const mockResponse: ApiResponse<{ results: Array<{ id: string; score: number }> }> = {
        success: true,
        data: { results: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.searchSimilar({
        namespace: 'documents',
        id: 'vec-1',
        topK: 5,
        includeMetadata: true,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/vector/search/similar', {
        namespace: 'documents',
        id: 'vec-1',
        topK: 5,
        includeMetadata: true,
      });
    });

    it('should handle vector not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Vector not found' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.searchSimilar({
        namespace: 'documents',
        id: 'nonexistent',
        topK: 5,
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });
  });

  // =========================================================================
  // delete() tests
  // =========================================================================

  describe('delete', () => {
    it('should delete vectors by IDs', async () => {
      const mockResponse: ApiResponse<{ deletedCount: number }> = {
        success: true,
        data: { deletedCount: 2 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.delete({
        namespace: 'documents',
        ids: ['vec-1', 'vec-2'],
      });

      expect(result.success).toBe(true);
      expect(result.data?.deletedCount).toBe(2);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/vector/delete', {
        namespace: 'documents',
        ids: ['vec-1', 'vec-2'],
      });
    });

    it('should delete vectors by filter', async () => {
      const mockResponse: ApiResponse<{ deletedCount: number }> = {
        success: true,
        data: { deletedCount: 10 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.delete({
        namespace: 'documents',
        filter: { category: 'deprecated' },
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/vector/delete', {
        namespace: 'documents',
        filter: { category: 'deprecated' },
      });
    });

    it('should delete all vectors in namespace', async () => {
      const mockResponse: ApiResponse<{ deletedCount: number }> = {
        success: true,
        data: { deletedCount: 1000 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.delete({
        namespace: 'documents',
        deleteAll: true,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/vector/delete', {
        namespace: 'documents',
        deleteAll: true,
      });
    });

    it('should handle delete error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INTERNAL_ERROR', message: 'Delete operation failed' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.delete({
        namespace: 'documents',
        ids: ['vec-1'],
      });

      expect(result.success).toBe(false);
    });
  });

  // =========================================================================
  // createNamespace() tests
  // =========================================================================

  describe('createNamespace', () => {
    it('should create a namespace', async () => {
      const mockResponse: ApiResponse<{ name: string; dimension: number; metric: string }> = {
        success: true,
        data: { name: 'embeddings', dimension: 1536, metric: 'COSINE' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.createNamespace({
        name: 'embeddings',
        dimension: 1536,
        metric: 'COSINE',
      });

      expect(result.success).toBe(true);
      expect(result.data).toMatchObject({ name: 'embeddings' });
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/vector/namespaces', {
        name: 'embeddings',
        dimension: 1536,
        metric: 'COSINE',
      });
    });

    it('should create namespace with index config', async () => {
      const mockResponse: ApiResponse<{ name: string; dimension: number; metric: string }> = {
        success: true,
        data: { name: 'embeddings', dimension: 1536, metric: 'COSINE' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.createNamespace({
        name: 'embeddings',
        dimension: 1536,
        metric: 'COSINE',
        indexConfig: {
          type: 'hnsw',
          hnswM: 16,
          hnswEfConstruction: 200,
        },
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/vector/namespaces', {
        name: 'embeddings',
        dimension: 1536,
        metric: 'COSINE',
        indexConfig: {
          type: 'hnsw',
          hnswM: 16,
          hnswEfConstruction: 200,
        },
      });
    });

    it('should handle namespace already exists error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'ALREADY_EXISTS', message: 'Namespace already exists' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.createNamespace({
        name: 'embeddings',
        dimension: 1536,
        metric: 'COSINE',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('ALREADY_EXISTS');
    });
  });

  // =========================================================================
  // deleteNamespace() tests
  // =========================================================================

  describe('deleteNamespace', () => {
    it('should delete a namespace', async () => {
      const mockResponse: ApiResponse<{ deleted: boolean }> = {
        success: true,
        data: { deleted: true },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      const result = await service.deleteNamespace({ name: 'old-embeddings' });

      expect(result.success).toBe(true);
      expect(mockClient.delete).toHaveBeenCalledWith('/v1/quicbaas/vector/namespaces/old-embeddings');
    });

    it('should delete namespace with force option', async () => {
      const mockResponse: ApiResponse<{ deleted: boolean }> = {
        success: true,
        data: { deleted: true },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      await service.deleteNamespace({ name: 'embeddings', force: true });

      expect(mockClient.delete).toHaveBeenCalledWith(
        expect.stringContaining('force=true')
      );
    });

    it('should handle namespace not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Namespace not found' },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      const result = await service.deleteNamespace({ name: 'nonexistent' });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });
  });

  // =========================================================================
  // listNamespaces() tests
  // =========================================================================

  describe('listNamespaces', () => {
    it('should list all namespaces', async () => {
      const mockResponse: ApiResponse<{
        namespaces: Array<{ name: string; dimension: number; vectorCount: number }>;
      }> = {
        success: true,
        data: {
          namespaces: [
            { name: 'docs', dimension: 1536, vectorCount: 1000 },
            { name: 'images', dimension: 512, vectorCount: 500 },
          ],
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.listNamespaces();

      expect(result.success).toBe(true);
      expect(result.data?.namespaces).toHaveLength(2);
      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('/v1/quicbaas/vector/namespaces')
      );
    });

    it('should list namespaces with pagination', async () => {
      const mockResponse: ApiResponse<{ namespaces: unknown[] }> = {
        success: true,
        data: { namespaces: [] },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.listNamespaces({ limit: 10, cursor: 'page-2' });

      const call = vi.mocked(mockClient.get).mock.calls[0]![0];
      expect(call).toContain('limit=10');
      expect(call).toContain('cursor=page-2');
    });

    it('should list namespaces with prefix filter', async () => {
      const mockResponse: ApiResponse<{ namespaces: unknown[] }> = {
        success: true,
        data: { namespaces: [] },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.listNamespaces({ prefix: 'prod-' });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('prefix=prod-')
      );
    });
  });

  // =========================================================================
  // getStats() tests
  // =========================================================================

  describe('getStats', () => {
    it('should get overall vector stats', async () => {
      const mockResponse: ApiResponse<{
        stats: { totalVectorCount: number; totalNamespaces: number };
      }> = {
        success: true,
        data: {
          stats: { totalVectorCount: 10000, totalNamespaces: 5 },
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.getStats();

      expect(result.success).toBe(true);
      expect(result.data?.stats.totalVectorCount).toBe(10000);
      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('/v1/quicbaas/vector/stats')
      );
    });

    it('should get stats for specific namespace', async () => {
      const mockResponse: ApiResponse<{ stats: { totalVectorCount: number } }> = {
        success: true,
        data: { stats: { totalVectorCount: 1000 } },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.getStats({ namespace: 'documents' });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('namespace=documents')
      );
    });

    it('should handle stats error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INTERNAL_ERROR', message: 'Failed to get stats' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.getStats();

      expect(result.success).toBe(false);
    });
  });
});
