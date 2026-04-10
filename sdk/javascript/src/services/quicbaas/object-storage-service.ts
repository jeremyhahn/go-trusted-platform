/**
 * QuicBaaS Object Storage Service
 *
 * Provides operations for distributed object storage including
 * put, get, delete, list, head, and copy operations.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  PutObjectRequest,
  PutObjectResponse,
  GetObjectRequest,
  GetObjectResponse,
  DeleteObjectRequest,
  DeleteObjectResponse,
  ListObjectsRequest,
  ListObjectsResponse,
  HeadObjectRequest,
  HeadObjectResponse,
  CopyObjectRequest,
  CopyObjectResponse,
} from '../../types/quicbaas/infrastructure-part2.js';

/**
 * QuicBaaS Object Storage Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Put an object
 * const putResult = await client.quicbaas.objectStorage.putObject({
 *   bucket: 'my-bucket',
 *   key: 'documents/file.txt',
 *   content: btoa('Hello, World!'),
 *   contentType: 'text/plain',
 * });
 *
 * // Get the object
 * const getResult = await client.quicbaas.objectStorage.getObject({
 *   bucket: 'my-bucket',
 *   key: 'documents/file.txt',
 * });
 *
 * // List objects with prefix
 * const listResult = await client.quicbaas.objectStorage.listObjects({
 *   bucket: 'my-bucket',
 *   prefix: 'documents/',
 * });
 * ```
 */
export class ObjectStorageService extends BaseService {
  /**
   * Creates a new Object Storage service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  // =========================================================================
  // Object Operations
  // =========================================================================

  /**
   * Put an object into storage
   *
   * @param request - Put object request with content
   * @returns Put result with ETag
   */
  async putObject(request: PutObjectRequest): Promise<ApiResponse<PutObjectResponse>> {
    return this.client.post<PutObjectResponse>(
      this.buildUrl(`/storage/buckets/${this.encodePathSegment(request.bucket)}/objects`),
      {
        key: request.key,
        content: request.content,
        contentType: request.contentType,
        storageClass: request.storageClass,
        metadata: request.metadata,
        ifMatch: request.ifMatch,
        ifNoneMatch: request.ifNoneMatch,
      }
    );
  }

  /**
   * Get an object from storage
   *
   * @param request - Get object request
   * @returns Object with content
   */
  async getObject(request: GetObjectRequest): Promise<ApiResponse<GetObjectResponse>> {
    const filters: Record<string, string | undefined> = {};

    if (request.versionId !== undefined) {
      filters.versionId = request.versionId;
    }
    if (request.range !== undefined) {
      filters.range = request.range;
    }
    if (request.ifModifiedSince !== undefined) {
      filters.ifModifiedSince = request.ifModifiedSince;
    }
    if (request.ifNoneMatch !== undefined) {
      filters.ifNoneMatch = request.ifNoneMatch;
    }

    return this.client.get<GetObjectResponse>(
      this.buildUrl(
        `/storage/buckets/${this.encodePathSegment(request.bucket)}/objects/${this.encodePathSegment(request.key)}`,
        { filters }
      )
    );
  }

  /**
   * Delete an object from storage
   *
   * @param request - Delete object request
   * @returns Deletion result
   */
  async deleteObject(request: DeleteObjectRequest): Promise<ApiResponse<DeleteObjectResponse>> {
    const filters: Record<string, string | undefined> = {};

    if (request.versionId !== undefined) {
      filters.versionId = request.versionId;
    }

    return this.client.delete<DeleteObjectResponse>(
      this.buildUrl(
        `/storage/buckets/${this.encodePathSegment(request.bucket)}/objects/${this.encodePathSegment(request.key)}`,
        { filters }
      )
    );
  }

  /**
   * List objects in a bucket
   *
   * @param request - List objects request with filters
   * @returns List of objects
   */
  async listObjects(request: ListObjectsRequest): Promise<ApiResponse<ListObjectsResponse>> {
    const filters: Record<string, string | undefined> = {};

    if (request.prefix !== undefined) {
      filters.prefix = request.prefix;
    }
    if (request.delimiter !== undefined) {
      filters.delimiter = request.delimiter;
    }
    if (request.startAfter !== undefined) {
      filters.startAfter = request.startAfter;
    }
    if (request.maxKeys !== undefined) {
      filters.maxKeys = request.maxKeys.toString();
    }
    if (request.cursor !== undefined) {
      filters.continuationToken = request.cursor;
    }

    return this.client.get<ListObjectsResponse>(
      this.buildUrl(
        `/storage/buckets/${this.encodePathSegment(request.bucket)}/objects`,
        {
          page: request.page,
          limit: request.pageSize,
          filters,
        }
      )
    );
  }

  /**
   * Get object metadata without content (HEAD operation)
   *
   * @param request - Head object request
   * @returns Object metadata
   */
  async headObject(request: HeadObjectRequest): Promise<ApiResponse<HeadObjectResponse>> {
    const filters: Record<string, string | undefined> = {};

    if (request.versionId !== undefined) {
      filters.versionId = request.versionId;
    }

    return this.client.get<HeadObjectResponse>(
      this.buildUrl(
        `/storage/buckets/${this.encodePathSegment(request.bucket)}/objects/${this.encodePathSegment(request.key)}/metadata`,
        { filters }
      )
    );
  }

  /**
   * Copy an object within or between buckets
   *
   * @param request - Copy object request
   * @returns Copy result
   */
  async copyObject(request: CopyObjectRequest): Promise<ApiResponse<CopyObjectResponse>> {
    return this.client.post<CopyObjectResponse>(
      this.buildUrl(
        `/storage/buckets/${this.encodePathSegment(request.destinationBucket)}/objects/copy`
      ),
      {
        sourceBucket: request.sourceBucket,
        sourceKey: request.sourceKey,
        sourceVersionId: request.sourceVersionId,
        destinationKey: request.destinationKey,
        metadata: request.metadata,
        storageClass: request.storageClass,
      }
    );
  }
}
