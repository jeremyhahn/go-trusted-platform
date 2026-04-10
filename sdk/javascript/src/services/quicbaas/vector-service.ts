/**
 * QuicBaaS Vector Service
 *
 * Provides vector similarity search operations including k-NN search,
 * namespace management, and index statistics.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  VectorInsertRequest,
  VectorInsertResponse,
  VectorSearchRequest,
  VectorSearchResponse,
  VectorSearchSimilarRequest,
  VectorDeleteRequest,
  VectorDeleteResponse,
  CreateNamespaceRequest,
  CreateNamespaceResponse,
  DeleteNamespaceRequest,
  DeleteNamespaceResponse,
  ListNamespacesRequest,
  ListNamespacesResponse,
  GetVectorStatsRequest,
  GetVectorStatsResponse,
} from '../../types/quicbaas/ai-ml.js';

/**
 * QuicBaaS Vector Service class
 *
 * Provides vector similarity search (k-NN) operations for AI/ML workloads.
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a namespace for vectors
 * const ns = await client.quicbaas.vector.createNamespace({
 *   name: 'documents',
 *   dimension: 1536,
 *   metric: 'COSINE',
 * });
 *
 * // Insert vectors
 * const inserted = await client.quicbaas.vector.insert({
 *   namespace: 'documents',
 *   vectors: [
 *     { id: 'doc-1', values: [...], metadata: { title: 'Document 1' } },
 *     { id: 'doc-2', values: [...], metadata: { title: 'Document 2' } },
 *   ],
 * });
 *
 * // Search for similar vectors
 * const results = await client.quicbaas.vector.search({
 *   namespace: 'documents',
 *   vector: queryVector,
 *   topK: 10,
 *   includeMetadata: true,
 * });
 * ```
 */
export class VectorService extends BaseService {
  /**
   * Creates a new Vector service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas/vector');
  }

  // =========================================================================
  // Vector Operations
  // =========================================================================

  /**
   * Insert vectors into a namespace
   *
   * @param request - Vector insert request with vectors and optional namespace
   * @returns Insert result with count and IDs of inserted vectors
   *
   * @example
   * ```typescript
   * const result = await vectorService.insert({
   *   namespace: 'my-namespace',
   *   vectors: [
   *     {
   *       id: 'vec-1',
   *       values: [0.1, 0.2, 0.3, ...],
   *       metadata: { category: 'example' },
   *     },
   *   ],
   *   overwrite: true,
   * });
   * console.log(`Inserted ${result.data.insertedCount} vectors`);
   * ```
   */
  async insert(request: VectorInsertRequest): Promise<ApiResponse<VectorInsertResponse>> {
    return this.client.post<VectorInsertResponse>(this.buildUrl('/insert'), request);
  }

  /**
   * Search for similar vectors using a query vector
   *
   * Performs k-nearest neighbor (k-NN) search to find vectors most similar
   * to the provided query vector.
   *
   * @param request - Vector search request with query vector and parameters
   * @returns Search results with scores and optional metadata
   *
   * @example
   * ```typescript
   * const results = await vectorService.search({
   *   namespace: 'documents',
   *   vector: [0.1, 0.2, 0.3, ...],
   *   topK: 10,
   *   scoreThreshold: 0.8,
   *   includeMetadata: true,
   *   filter: { category: 'technology' },
   * });
   *
   * for (const result of results.data.results) {
   *   console.log(`ID: ${result.id}, Score: ${result.score}`);
   * }
   * ```
   */
  async search(request: VectorSearchRequest): Promise<ApiResponse<VectorSearchResponse>> {
    return this.client.post<VectorSearchResponse>(this.buildUrl('/search'), request);
  }

  /**
   * Search for vectors similar to an existing vector by ID
   *
   * Finds vectors similar to a vector that already exists in the index,
   * identified by its ID.
   *
   * @param request - Similar search request with vector ID and parameters
   * @returns Search results with scores and optional metadata
   *
   * @example
   * ```typescript
   * const results = await vectorService.searchSimilar({
   *   namespace: 'documents',
   *   id: 'doc-123',
   *   topK: 5,
   *   includeMetadata: true,
   * });
   * ```
   */
  async searchSimilar(request: VectorSearchSimilarRequest): Promise<ApiResponse<VectorSearchResponse>> {
    return this.client.post<VectorSearchResponse>(this.buildUrl('/search/similar'), request);
  }

  /**
   * Delete vectors from a namespace
   *
   * Vectors can be deleted by ID, by filter, or all vectors in a namespace.
   *
   * @param request - Delete request with IDs, filter, or deleteAll flag
   * @returns Delete result with count of deleted vectors
   *
   * @example
   * ```typescript
   * // Delete by IDs
   * await vectorService.delete({
   *   namespace: 'documents',
   *   ids: ['doc-1', 'doc-2'],
   * });
   *
   * // Delete by filter
   * await vectorService.delete({
   *   namespace: 'documents',
   *   filter: { category: 'deprecated' },
   * });
   *
   * // Delete all vectors in namespace
   * await vectorService.delete({
   *   namespace: 'documents',
   *   deleteAll: true,
   * });
   * ```
   */
  async delete(request: VectorDeleteRequest): Promise<ApiResponse<VectorDeleteResponse>> {
    return this.client.post<VectorDeleteResponse>(this.buildUrl('/delete'), request);
  }

  // =========================================================================
  // Namespace Operations
  // =========================================================================

  /**
   * Create a new vector namespace
   *
   * A namespace isolates vectors and defines the dimension and distance metric
   * for all vectors within it.
   *
   * @param request - Namespace creation request with name, dimension, and metric
   * @returns Created namespace information
   *
   * @example
   * ```typescript
   * const ns = await vectorService.createNamespace({
   *   name: 'embeddings',
   *   dimension: 1536,
   *   metric: 'COSINE',
   *   indexConfig: {
   *     type: 'hnsw',
   *     hnswM: 16,
   *     hnswEfConstruction: 200,
   *   },
   * });
   * ```
   */
  async createNamespace(request: CreateNamespaceRequest): Promise<ApiResponse<CreateNamespaceResponse>> {
    return this.client.post<CreateNamespaceResponse>(this.buildUrl('/namespaces'), request);
  }

  /**
   * Delete a vector namespace
   *
   * Deletes a namespace and all vectors within it.
   *
   * @param request - Delete request with namespace name
   * @returns Delete result
   *
   * @example
   * ```typescript
   * await vectorService.deleteNamespace({
   *   name: 'old-embeddings',
   *   force: true,
   * });
   * ```
   */
  async deleteNamespace(request: DeleteNamespaceRequest): Promise<ApiResponse<DeleteNamespaceResponse>> {
    const url = this.buildUrl(`/namespaces/${this.encodePathSegment(request.name)}`, {
      filters: {
        force: request.force?.toString(),
      },
    });
    return this.client.delete<DeleteNamespaceResponse>(url);
  }

  /**
   * List all vector namespaces
   *
   * @param options - List options with pagination and filtering
   * @returns List of namespaces
   *
   * @example
   * ```typescript
   * const namespaces = await vectorService.listNamespaces({
   *   limit: 100,
   *   prefix: 'prod-',
   * });
   *
   * for (const ns of namespaces.data.namespaces) {
   *   console.log(`${ns.name}: ${ns.vectorCount} vectors`);
   * }
   * ```
   */
  async listNamespaces(options?: ListNamespacesRequest): Promise<ApiResponse<ListNamespacesResponse>> {
    return this.client.get<ListNamespacesResponse>(this.buildUrl('/namespaces', {
      limit: options?.limit,
      filters: {
        cursor: options?.cursor,
        prefix: options?.prefix,
      },
    }));
  }

  // =========================================================================
  // Statistics Operations
  // =========================================================================

  /**
   * Get vector index statistics
   *
   * Returns statistics about the vector index including total vector count,
   * index size, and per-namespace statistics.
   *
   * @param request - Optional request to filter by namespace
   * @returns Index statistics
   *
   * @example
   * ```typescript
   * // Get overall stats
   * const stats = await vectorService.getStats({});
   * console.log(`Total vectors: ${stats.data.stats.totalVectorCount}`);
   *
   * // Get stats for specific namespace
   * const nsStats = await vectorService.getStats({
   *   namespace: 'documents',
   * });
   * ```
   */
  async getStats(request?: GetVectorStatsRequest): Promise<ApiResponse<GetVectorStatsResponse>> {
    return this.client.get<GetVectorStatsResponse>(this.buildUrl('/stats', {
      filters: {
        namespace: request?.namespace,
      },
    }));
  }
}
