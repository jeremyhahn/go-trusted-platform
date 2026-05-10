/**
 * QuicBaaS Object Storage Admin Service
 *
 * Provides administrative operations for object storage including
 * bucket management and policy configuration.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { Transport } from '../../transport/transport.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  CreateBucketRequest,
  CreateBucketResponse,
  DeleteBucketRequest,
  DeleteBucketResponse,
  ListBucketsRequest,
  ListBucketsResponse,
  GetBucketPolicyRequest,
  GetBucketPolicyResponse,
  SetBucketPolicyRequest,
  SetBucketPolicyResponse,
} from '../../types/quicbaas/infrastructure-part2.js';

/**
 * QuicBaaS Object Storage Admin Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a bucket
 * const bucket = await client.quicbaas.objectStorageAdmin.createBucket({
 *   name: 'my-bucket',
 *   region: 'us-east-1',
 *   config: {
 *     defaultStorageClass: 'standard',
 *     versioning: 'enabled',
 *     encryptionEnabled: true,
 *   },
 * });
 *
 * // Set bucket policy
 * await client.quicbaas.objectStorageAdmin.setBucketPolicy({
 *   bucket: 'my-bucket',
 *   policy: {
 *     version: '2012-10-17',
 *     statements: [{
 *       effect: 'allow',
 *       principals: ['*'],
 *       actions: ['s3:GetObject'],
 *       resources: ['my-bucket/*'],
 *     }],
 *   },
 * });
 *
 * // List all buckets
 * const buckets = await client.quicbaas.objectStorageAdmin.listBuckets({});
 * ```
 */
export class ObjectStorageAdminService extends BaseService {
  /**
   * Creates a new Object Storage Admin service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/quicbaas');
  }

  // =========================================================================
  // Bucket Management
  // =========================================================================

  /**
   * Create a new storage bucket
   *
   * @param request - Bucket creation request
   * @returns Created bucket
   */
  async createBucket(request: CreateBucketRequest): Promise<ApiResponse<CreateBucketResponse>> {
    return this.client.post<CreateBucketResponse>(
      this.buildUrl('/storage/buckets'),
      request
    );
  }

  /**
   * Delete a storage bucket
   *
   * @param request - Delete bucket request
   * @returns Deletion result
   */
  async deleteBucket(request: DeleteBucketRequest): Promise<ApiResponse<DeleteBucketResponse>> {
    const url = this.buildUrl(`/storage/buckets/${this.encodePathSegment(request.name)}`, {
      filters: {
        force: request.force?.toString(),
      },
    });
    return this.client.delete<DeleteBucketResponse>(url);
  }

  /**
   * List all storage buckets
   *
   * @param request - List buckets request with optional filters
   * @returns List of buckets
   */
  async listBuckets(request?: ListBucketsRequest): Promise<ApiResponse<ListBucketsResponse>> {
    const filters: Record<string, string | undefined> = {};

    if (request?.region !== undefined) {
      filters.region = request.region;
    }

    return this.client.get<ListBucketsResponse>(
      this.buildUrl('/storage/buckets', {
        page: request?.page,
        limit: request?.pageSize,
        filters,
      })
    );
  }

  // =========================================================================
  // Bucket Policy Management
  // =========================================================================

  /**
   * Get the policy for a bucket
   *
   * @param request - Get bucket policy request
   * @returns Bucket policy
   */
  async getBucketPolicy(request: GetBucketPolicyRequest): Promise<ApiResponse<GetBucketPolicyResponse>> {
    return this.client.get<GetBucketPolicyResponse>(
      this.buildUrl(`/storage/buckets/${this.encodePathSegment(request.bucket)}/policy`)
    );
  }

  /**
   * Set or update the policy for a bucket
   *
   * @param request - Set bucket policy request
   * @returns Operation result
   */
  async setBucketPolicy(request: SetBucketPolicyRequest): Promise<ApiResponse<SetBucketPolicyResponse>> {
    return this.client.put<SetBucketPolicyResponse>(
      this.buildUrl(`/storage/buckets/${this.encodePathSegment(request.bucket)}/policy`),
      { policy: request.policy }
    );
  }
}
