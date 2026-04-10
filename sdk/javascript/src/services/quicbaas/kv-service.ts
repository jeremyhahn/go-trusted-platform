/**
 * QuicBaaS Key-Value Service
 *
 * Provides key-value CRUD operations with watch support for real-time updates.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  KVGetRequest,
  KVGetResponse,
  KVPutRequest,
  KVPutResponse,
  KVDeleteRequest,
  KVDeleteResponse,
  KVListRequest,
  KVListResponse,
  KVWatchRequest,
  KVWatchResponse,
} from '../../types/quicbaas/core-data.js';

/**
 * QuicBaaS Key-Value Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Put a value
 * const putResult = await client.quicbaas.kv.put({
 *   key: 'users/user-123',
 *   value: btoa(JSON.stringify({ name: 'John', email: 'john@example.com' })),
 *   ttl: 3600, // 1 hour expiration
 * });
 *
 * // Get a value
 * const getResult = await client.quicbaas.kv.get({ key: 'users/user-123' });
 *
 * // List keys with prefix
 * const listResult = await client.quicbaas.kv.list({ prefix: 'users/' });
 *
 * // Watch for changes
 * const watchResult = await client.quicbaas.kv.watch({
 *   prefix: 'users/',
 *   eventTypes: ['PUT', 'DELETE'],
 * });
 * ```
 */
export class KVService extends BaseService {
  /**
   * Creates a new KV service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  /**
   * Get a value by key
   *
   * Retrieves a key-value pair from the store. Supports specifying consistency
   * level and retrieving specific versions.
   *
   * @param request - Get request with key and options
   * @returns Key-value pair if found
   */
  async get(request: KVGetRequest): Promise<ApiResponse<KVGetResponse>> {
    const params: Record<string, string | number | undefined> = {};

    if (request.consistency !== undefined) {
      params.consistency = request.consistency;
    }

    if (request.version !== undefined) {
      params.version = request.version;
    }

    return this.client.get<KVGetResponse>(
      this.buildUrl(`/kv/${this.encodePathSegment(request.key)}`, {
        filters: params,
      })
    );
  }

  /**
   * Put a value
   *
   * Stores a key-value pair with optional TTL and metadata.
   * Supports conditional writes with ifNotExists and ifVersion.
   *
   * @param request - Put request with key, value, and options
   * @returns Put result with new version number
   */
  async put(request: KVPutRequest): Promise<ApiResponse<KVPutResponse>> {
    return this.client.post<KVPutResponse>(
      this.buildUrl('/kv'),
      {
        key: request.key,
        value: request.value,
        ttl: request.ttl,
        metadata: request.metadata,
        ifNotExists: request.ifNotExists,
        ifVersion: request.ifVersion,
      }
    );
  }

  /**
   * Delete a value by key
   *
   * Removes a key-value pair from the store. Supports conditional delete
   * with version matching.
   *
   * @param request - Delete request with key and options
   * @returns Delete result with previous value if existed
   */
  async delete(request: KVDeleteRequest): Promise<ApiResponse<KVDeleteResponse>> {
    const params: Record<string, string | number | undefined> = {};

    if (request.ifVersion !== undefined) {
      params.ifVersion = request.ifVersion;
    }

    return this.client.delete<KVDeleteResponse>(
      this.buildUrl(`/kv/${this.encodePathSegment(request.key)}`, {
        filters: params,
      })
    );
  }

  /**
   * List keys with optional filtering
   *
   * Retrieves a list of key-value pairs with support for prefix filtering,
   * range queries, and pagination.
   *
   * @param request - List request with filter and pagination options
   * @returns List of key-value pairs
   */
  async list(request?: KVListRequest): Promise<ApiResponse<KVListResponse>> {
    const params: Record<string, string | number | boolean | undefined> = {};

    if (request?.prefix !== undefined) {
      params.prefix = request.prefix;
    }

    if (request?.startKey !== undefined) {
      params.startKey = request.startKey;
    }

    if (request?.endKey !== undefined) {
      params.endKey = request.endKey;
    }

    if (request?.limit !== undefined) {
      params.limit = request.limit;
    }

    if (request?.cursor !== undefined) {
      params.cursor = request.cursor;
    }

    if (request?.includeValues !== undefined) {
      params.includeValues = request.includeValues;
    }

    if (request?.consistency !== undefined) {
      params.consistency = request.consistency;
    }

    return this.client.get<KVListResponse>(
      this.buildUrl('/kv', { filters: params })
    );
  }

  /**
   * Watch for changes on keys
   *
   * Establishes a watch on keys matching the specified key or prefix.
   * Returns events for changes that occur after the watch is established.
   *
   * Note: This initiates a watch and returns the watch ID and initial events.
   * Use a WebSocket or SSE connection for real-time streaming.
   *
   * @param request - Watch request with key/prefix and filter options
   * @returns Watch response with watch ID and events
   */
  async watch(request: KVWatchRequest): Promise<ApiResponse<KVWatchResponse>> {
    return this.client.post<KVWatchResponse>(
      this.buildUrl('/kv/watch'),
      {
        key: request.key,
        prefix: request.prefix,
        startRevision: request.startRevision,
        eventTypes: request.eventTypes,
      }
    );
  }
}
