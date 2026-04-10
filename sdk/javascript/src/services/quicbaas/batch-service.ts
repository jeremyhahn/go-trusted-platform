/**
 * QuicBaaS Batch Service
 *
 * Provides atomic batch operations for efficient bulk read/write operations.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  BatchGetRequest,
  BatchGetResponse,
  BatchPutRequest,
  BatchPutResponse,
  BatchDeleteRequest,
  BatchDeleteResponse,
} from '../../types/quicbaas/core-data.js';

/**
 * QuicBaaS Batch Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Batch get multiple keys
 * const getResult = await client.quicbaas.batch.batchGet({
 *   keys: ['users/user-1', 'users/user-2', 'users/user-3'],
 *   consistency: 'STRONG',
 * });
 *
 * // Batch put multiple items
 * const putResult = await client.quicbaas.batch.batchPut({
 *   items: [
 *     { key: 'config/setting-1', value: btoa('value1') },
 *     { key: 'config/setting-2', value: btoa('value2'), ttl: 3600 },
 *   ],
 *   atomic: true, // All or nothing
 * });
 *
 * // Batch delete multiple keys
 * const deleteResult = await client.quicbaas.batch.batchDelete({
 *   keys: ['temp/file-1', 'temp/file-2'],
 *   atomic: false,
 * });
 * ```
 */
export class BatchService extends BaseService {
  /**
   * Creates a new Batch service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  /**
   * Batch get multiple keys
   *
   * Retrieves multiple key-value pairs in a single request. Keys that do not
   * exist will have null values in the response array at their corresponding
   * positions.
   *
   * @param request - Batch get request with keys and consistency level
   * @returns Array of key-value pairs (null for missing keys)
   */
  async batchGet(request: BatchGetRequest): Promise<ApiResponse<BatchGetResponse>> {
    return this.client.post<BatchGetResponse>(
      this.buildUrl('/batch/get'),
      {
        keys: request.keys,
        consistency: request.consistency,
      }
    );
  }

  /**
   * Batch put multiple items
   *
   * Stores multiple key-value pairs in a single request. Supports atomic mode
   * where all items are committed together or the entire operation fails.
   *
   * @param request - Batch put request with items and atomic flag
   * @returns Results for each item with success/failure status
   */
  async batchPut(request: BatchPutRequest): Promise<ApiResponse<BatchPutResponse>> {
    return this.client.post<BatchPutResponse>(
      this.buildUrl('/batch/put'),
      {
        items: request.items,
        atomic: request.atomic,
      }
    );
  }

  /**
   * Batch delete multiple keys
   *
   * Deletes multiple key-value pairs in a single request. Supports atomic mode
   * where all deletes are committed together or the entire operation fails.
   *
   * @param request - Batch delete request with keys and atomic flag
   * @returns Results for each key with success/failure status
   */
  async batchDelete(request: BatchDeleteRequest): Promise<ApiResponse<BatchDeleteResponse>> {
    return this.client.post<BatchDeleteResponse>(
      this.buildUrl('/batch/delete'),
      {
        keys: request.keys,
        atomic: request.atomic,
      }
    );
  }
}
