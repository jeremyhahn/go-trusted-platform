/**
 * QuicBaaS Query Service
 *
 * Provides secondary index queries for efficient data retrieval by field values.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  QueryRequest,
  QueryResponse,
  CreateIndexRequest,
  CreateIndexResponse,
  DeleteIndexRequest,
  DeleteIndexResponse,
  ListIndexesRequest,
  ListIndexesResponse,
} from '../../types/quicbaas/core-data.js';

/**
 * QuicBaaS Query Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a secondary index
 * const indexResult = await client.quicbaas.query.createIndex({
 *   name: 'users_by_email',
 *   prefix: 'users/',
 *   type: 'BTREE',
 *   fields: [{ field: 'email', order: 'ASC' }],
 *   unique: true,
 * });
 *
 * // Query using the index
 * const queryResult = await client.quicbaas.query.query({
 *   prefix: 'users/',
 *   filters: [
 *     { field: 'status', operator: 'EQ', value: 'active' },
 *     { field: 'createdAt', operator: 'GTE', value: 1704067200000 },
 *   ],
 *   sorts: [{ field: 'createdAt', order: 'DESC' }],
 *   limit: 10,
 * });
 *
 * // List all indexes
 * const indexesResult = await client.quicbaas.query.listIndexes({});
 *
 * // Delete an index
 * const deleteResult = await client.quicbaas.query.deleteIndex({
 *   name: 'users_by_email',
 * });
 * ```
 */
export class QueryService extends BaseService {
  /**
   * Creates a new Query service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  /**
   * Query data using secondary indexes
   *
   * Executes a query against the data store using filters, sorts, and
   * projections. Queries leverage secondary indexes for efficient retrieval.
   *
   * @param request - Query request with filters, sorts, and pagination
   * @returns Query results with pagination metadata
   */
  async query(request: QueryRequest): Promise<ApiResponse<QueryResponse>> {
    return this.client.post<QueryResponse>(
      this.buildUrl('/query'),
      {
        prefix: request.prefix,
        filters: request.filters,
        sorts: request.sorts,
        projection: request.projection,
        limit: request.limit,
        offset: request.offset,
        cursor: request.cursor,
        consistency: request.consistency,
      }
    );
  }

  /**
   * Create a secondary index
   *
   * Creates a new secondary index on the specified fields. Indexes improve
   * query performance for frequently accessed fields.
   *
   * @param request - Create index request with name, fields, and options
   * @returns Index metadata
   */
  async createIndex(request: CreateIndexRequest): Promise<ApiResponse<CreateIndexResponse>> {
    return this.client.post<CreateIndexResponse>(
      this.buildUrl('/indexes'),
      {
        name: request.name,
        prefix: request.prefix,
        type: request.type,
        fields: request.fields,
        background: request.background,
        unique: request.unique,
        sparse: request.sparse,
      }
    );
  }

  /**
   * Delete a secondary index
   *
   * Removes an existing secondary index. Queries that relied on this index
   * will fall back to full scans.
   *
   * @param request - Delete index request with index name
   * @returns Deletion confirmation
   */
  async deleteIndex(request: DeleteIndexRequest): Promise<ApiResponse<DeleteIndexResponse>> {
    return this.client.delete<DeleteIndexResponse>(
      this.buildUrl(`/indexes/${this.encodePathSegment(request.name)}`)
    );
  }

  /**
   * List all secondary indexes
   *
   * Retrieves a list of all secondary indexes with their metadata including
   * state, size, and entry count.
   *
   * @param request - List indexes request with optional filters
   * @returns List of index metadata
   */
  async listIndexes(request?: ListIndexesRequest): Promise<ApiResponse<ListIndexesResponse>> {
    const params: Record<string, string | number | undefined> = {};

    if (request?.prefix !== undefined) {
      params.prefix = request.prefix;
    }

    if (request?.limit !== undefined) {
      params.limit = request.limit;
    }

    if (request?.cursor !== undefined) {
      params.cursor = request.cursor;
    }

    return this.client.get<ListIndexesResponse>(
      this.buildUrl('/indexes', { filters: params })
    );
  }
}
