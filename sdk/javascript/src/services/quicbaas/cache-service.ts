/**
 * QuicBaaS Cache Service
 *
 * Provides operations for distributed cache management including
 * get, put, delete operations and cache statistics.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  CacheGetRequest,
  CacheGetResponse,
  CachePutRequest,
  CachePutResponse,
  CacheDeleteRequest,
  CacheDeleteResponse,
  CacheClearRequest,
  CacheClearResponse,
  CacheStatsResponse,
  SetTTLRequest,
  SetTTLResponse,
} from '../../types/quicbaas/infrastructure-part1.js';

/**
 * QuicBaaS Cache Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Put a value in cache
 * await client.quicbaas.cache.put({
 *   key: 'user:123',
 *   value: JSON.stringify({ name: 'John', email: 'john@example.com' }),
 *   valueType: 'json',
 *   ttlSeconds: 3600
 * });
 *
 * // Get a value from cache
 * const result = await client.quicbaas.cache.get({ key: 'user:123' });
 * if (result.data.found) {
 *   const user = JSON.parse(result.data.value);
 *   console.log(`User: ${user.name}`);
 * }
 *
 * // Get cache statistics
 * const stats = await client.quicbaas.cache.getStats();
 * console.log(`Hit ratio: ${(stats.data.hitRatio * 100).toFixed(2)}%`);
 *
 * // Clear cache by pattern
 * await client.quicbaas.cache.clear({ pattern: 'user:*' });
 * ```
 */
export class CacheService extends BaseService {
  /**
   * Creates a new Cache service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  /**
   * Get a value from cache
   *
   * Retrieves a cached value by key. Returns found: false if
   * the key does not exist or has expired.
   *
   * @param request - Get request with key and optional namespace
   * @returns Cached value if found
   */
  async get(request: CacheGetRequest): Promise<ApiResponse<CacheGetResponse>> {
    const url = this.buildUrl(`/cache/${this.encodePathSegment(request.key)}`, {
      filters: {
        namespace: request.namespace,
      },
    });
    return this.client.get<CacheGetResponse>(url);
  }

  /**
   * Put a value in cache
   *
   * Stores a value in the cache with an optional TTL. Binary
   * values should be base64 encoded.
   *
   * @param request - Put request with key, value, and options
   * @returns Put result with creation status
   */
  async put(request: CachePutRequest): Promise<ApiResponse<CachePutResponse>> {
    return this.client.post<CachePutResponse>(this.buildUrl('/cache'), request);
  }

  /**
   * Delete a value from cache
   *
   * Removes a cached value by key.
   *
   * @param request - Delete request with key and optional namespace
   * @returns Deletion result
   */
  async delete(request: CacheDeleteRequest): Promise<ApiResponse<CacheDeleteResponse>> {
    const url = this.buildUrl(`/cache/${this.encodePathSegment(request.key)}`, {
      filters: {
        namespace: request.namespace,
      },
    });
    return this.client.delete<CacheDeleteResponse>(url);
  }

  /**
   * Clear cache entries
   *
   * Removes multiple cache entries by namespace or pattern.
   * Use with caution as this operation cannot be undone.
   *
   * @param request - Clear request with optional namespace and pattern
   * @returns Number of cleared entries
   */
  async clear(request?: CacheClearRequest): Promise<ApiResponse<CacheClearResponse>> {
    return this.client.post<CacheClearResponse>(
      this.buildUrl('/cache/clear'),
      request ?? {}
    );
  }

  /**
   * Get cache statistics
   *
   * Returns comprehensive cache statistics including hit ratio,
   * size, and per-namespace breakdowns.
   *
   * @returns Cache statistics
   */
  async getStats(): Promise<ApiResponse<CacheStatsResponse>> {
    return this.client.get<CacheStatsResponse>(this.buildUrl('/cache/stats'));
  }

  /**
   * Set TTL for a cache key
   *
   * Updates the time-to-live for an existing cache key.
   * The key must exist for this operation to succeed.
   *
   * @param request - TTL update request
   * @returns Updated expiration information
   */
  async setTTL(request: SetTTLRequest): Promise<ApiResponse<SetTTLResponse>> {
    return this.client.patch<SetTTLResponse>(
      this.buildUrl(`/cache/${this.encodePathSegment(request.key)}/ttl`),
      {
        namespace: request.namespace,
        ttlSeconds: request.ttlSeconds,
      }
    );
  }
}
