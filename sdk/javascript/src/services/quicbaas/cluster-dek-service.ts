/**
 * QuicBaaS Cluster DEK Service
 *
 * Provides operations for cluster data encryption key management including
 * DEK generation, rotation, status monitoring, and key lifecycle management.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  QuicBaaSGenerateDEKRequest,
  QuicBaaSRotateDEKRequest,
  QuicBaaSGetDEKRequest,
  QuicBaaSListDEKsRequest,
  QuicBaaSGetClusterDEKStatusRequest,
  QuicBaaSGenerateDEKResponse,
  QuicBaaSRotateDEKResponse,
  QuicBaaSGetDEKResponse,
  QuicBaaSListDEKsResponse,
  QuicBaaSGetClusterDEKStatusResponse,
} from '../../types/quicbaas/security-part2.js';

/**
 * QuicBaaS Cluster DEK Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Generate a new cluster DEK
 * const dek = await client.quicbaas.clusterDEK.generateDEK({
 *   algorithm: 'AES_256_GCM',
 *   scope: 'DATABASE',
 *   scopeId: 'production-db',
 *   kekId: 'master-kek-001',
 *   autoRotate: true,
 *   rotationPeriodDays: 90,
 * });
 *
 * // Get cluster DEK status
 * const status = await client.quicbaas.clusterDEK.getStatus({
 *   includeNodeDetails: true,
 * });
 *
 * // Rotate a DEK
 * const rotated = await client.quicbaas.clusterDEK.rotateDEK({
 *   dekId: dek.data.dek?.dekId,
 * });
 * ```
 */
export class ClusterDEKService extends BaseService {
  /**
   * Creates a new Cluster DEK service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  // =========================================================================
  // DEK Management
  // =========================================================================

  /**
   * Generate a new data encryption key
   *
   * Creates a new DEK with the specified parameters and wraps it
   * with the designated key encryption key (KEK).
   *
   * @param request - DEK generation request
   * @returns Generated DEK metadata and wrapped key
   */
  async generateDEK(request: QuicBaaSGenerateDEKRequest): Promise<ApiResponse<QuicBaaSGenerateDEKResponse>> {
    return this.client.post<QuicBaaSGenerateDEKResponse>(
      this.buildUrl('/cluster/deks'),
      request
    );
  }

  /**
   * Rotate an existing data encryption key
   *
   * Creates a new version of the DEK while maintaining access
   * to data encrypted with previous versions.
   *
   * @param request - DEK rotation request
   * @returns Rotated DEK metadata with old and new versions
   */
  async rotateDEK(request: QuicBaaSRotateDEKRequest): Promise<ApiResponse<QuicBaaSRotateDEKResponse>> {
    return this.client.post<QuicBaaSRotateDEKResponse>(
      this.buildUrl(`/cluster/deks/${this.encodePathSegment(request.dekId)}/rotate`),
      {
        newAlgorithm: request.newAlgorithm,
        newKekId: request.newKekId,
        force: request.force,
      }
    );
  }

  /**
   * Get DEK by ID
   *
   * @param dekId - DEK identifier
   * @param options - Optional parameters
   * @returns DEK metadata and optional wrapped key material
   */
  async getDEK(
    dekId: string,
    options?: Omit<QuicBaaSGetDEKRequest, 'dekId'>
  ): Promise<ApiResponse<QuicBaaSGetDEKResponse>> {
    return this.client.get<QuicBaaSGetDEKResponse>(
      this.buildUrl(`/cluster/deks/${this.encodePathSegment(dekId)}`, {
        filters: {
          version: options?.version?.toString(),
          includeKeyMaterial: options?.includeKeyMaterial?.toString(),
        },
      })
    );
  }

  /**
   * List DEKs with optional filtering
   *
   * @param options - List options with filtering
   * @returns List of DEK metadata
   */
  async listDEKs(options?: QuicBaaSListDEKsRequest): Promise<ApiResponse<QuicBaaSListDEKsResponse>> {
    return this.client.get<QuicBaaSListDEKsResponse>(
      this.buildUrl('/cluster/deks', {
        limit: options?.limit,
        filters: {
          scope: options?.scope,
          scopeId: options?.scopeId,
          status: options?.status,
          kekId: options?.kekId,
          activeOnly: options?.activeOnly?.toString(),
          cursor: options?.cursor,
        },
      })
    );
  }

  // =========================================================================
  // Status and Monitoring
  // =========================================================================

  /**
   * Get cluster DEK status
   *
   * Returns overall health and status information for all DEKs
   * in the cluster, including rotation schedules and node status.
   *
   * @param options - Optional status request parameters
   * @returns Cluster DEK status with optional node details
   */
  async getStatus(options?: QuicBaaSGetClusterDEKStatusRequest): Promise<ApiResponse<QuicBaaSGetClusterDEKStatusResponse>> {
    return this.client.get<QuicBaaSGetClusterDEKStatusResponse>(
      this.buildUrl('/cluster/deks/status', {
        filters: {
          includeNodeDetails: options?.includeNodeDetails?.toString(),
          includePendingRotations: options?.includePendingRotations?.toString(),
        },
      })
    );
  }
}
