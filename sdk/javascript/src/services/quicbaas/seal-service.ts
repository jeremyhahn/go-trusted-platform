/**
 * QuicBaaS Seal Service
 *
 * Provides operations for seal/unseal functionality including
 * initialization, key share management, and seal status monitoring.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  QuicBaaSSealRequest,
  QuicBaaSUnsealRequest,
  QuicBaaSGetSealStatusRequest,
  QuicBaaSInitializeSealRequest,
  QuicBaaSRekeySealRequest,
  QuicBaaSSealResponse,
  QuicBaaSUnsealResponse,
  QuicBaaSGetSealStatusResponse,
  QuicBaaSInitializeSealResponse,
  QuicBaaSRekeySealResponse,
} from '../../types/quicbaas/security-part2.js';

/**
 * QuicBaaS Seal Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Initialize seal with Shamir secret sharing
 * const initResult = await client.quicbaas.seal.initialize({
 *   algorithm: 'SHAMIR',
 *   totalShares: 5,
 *   threshold: 3,
 * });
 *
 * // Get seal status
 * const status = await client.quicbaas.seal.getSealStatus();
 *
 * // Unseal with a key share
 * const unsealResult = await client.quicbaas.seal.unseal({
 *   share: 'base64-encoded-share',
 * });
 *
 * // Seal the cluster
 * const sealResult = await client.quicbaas.seal.seal();
 * ```
 */
export class SealService extends BaseService {
  /**
   * Creates a new Seal service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  // =========================================================================
  // Seal Operations
  // =========================================================================

  /**
   * Seal the cluster
   *
   * Sealing the cluster will encrypt all data at rest and require
   * unsealing with the configured threshold of key shares before
   * the cluster can be accessed again.
   *
   * @param request - Optional seal request parameters
   * @returns Seal result with new state
   */
  async seal(request?: QuicBaaSSealRequest): Promise<ApiResponse<QuicBaaSSealResponse>> {
    return this.client.post<QuicBaaSSealResponse>(
      this.buildUrl('/seal'),
      request ?? {}
    );
  }

  /**
   * Provide an unseal key share
   *
   * Multiple calls may be required to provide enough key shares
   * to meet the unseal threshold. Progress is returned in the response.
   *
   * @param request - Unseal request with key share
   * @returns Unseal progress and status
   */
  async unseal(request: QuicBaaSUnsealRequest): Promise<ApiResponse<QuicBaaSUnsealResponse>> {
    return this.client.post<QuicBaaSUnsealResponse>(
      this.buildUrl('/unseal'),
      request
    );
  }

  /**
   * Get current seal status
   *
   * @param options - Optional status request parameters
   * @returns Current seal status and configuration
   */
  async getSealStatus(options?: QuicBaaSGetSealStatusRequest): Promise<ApiResponse<QuicBaaSGetSealStatusResponse>> {
    return this.client.get<QuicBaaSGetSealStatusResponse>(
      this.buildUrl('/seal/status', {
        filters: {
          includeDetails: options?.includeDetails?.toString(),
        },
      })
    );
  }

  /**
   * Initialize the seal system
   *
   * This operation can only be performed once on a fresh cluster.
   * It generates the master key and splits it into the configured
   * number of key shares using the specified algorithm.
   *
   * @param request - Initialization parameters
   * @returns Generated key shares and root token
   */
  async initialize(request: QuicBaaSInitializeSealRequest): Promise<ApiResponse<QuicBaaSInitializeSealResponse>> {
    return this.client.post<QuicBaaSInitializeSealResponse>(
      this.buildUrl('/seal/init'),
      request
    );
  }

  /**
   * Rekey the seal
   *
   * This operation generates new key shares with potentially
   * different parameters. The cluster must be unsealed to perform
   * this operation. Rekeying is a multi-step process that requires
   * verification with existing key shares.
   *
   * @param request - Rekey parameters
   * @returns Rekey progress or new key shares if complete
   */
  async rekey(request: QuicBaaSRekeySealRequest): Promise<ApiResponse<QuicBaaSRekeySealResponse>> {
    return this.client.post<QuicBaaSRekeySealResponse>(
      this.buildUrl('/seal/rekey'),
      request
    );
  }
}
