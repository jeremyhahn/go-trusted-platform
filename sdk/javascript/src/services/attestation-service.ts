/**
 * Attestation Service
 *
 * Provides operations for attestation manifest management and quote operations.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  BuildManifestRequest,
  VerifyManifestRequest,
  ListManifestsRequest,
  GetAttestationQuoteRequest,
  VerifyAttestationQuoteRequest,
  CollectHostAttestationRequest,
  CollectVMAttestationRequest,
  CollectContainerAttestationRequest,
  GetManifestResponse,
  BuildManifestResponse,
  VerifyManifestResponse,
  ListManifestsResponse,
  DeleteManifestResponse,
  GetAttestationQuoteResponse,
  VerifyAttestationQuoteResponse,
  CollectHostAttestationResponse,
  CollectVMAttestationResponse,
  CollectContainerAttestationResponse,
} from '../types/attestation.js';

/**
 * Attestation Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Build a manifest
 * const manifest = await client.attestation.buildManifest({
 *   config: { hostId: 'host-1' },
 *   includeVms: true,
 *   sign: true,
 * });
 *
 * // Verify a manifest
 * const result = await client.attestation.verifyManifest({
 *   manifest: manifest.data.manifest,
 * });
 * ```
 */
export class AttestationService extends BaseService {
  /**
   * Creates a new Attestation service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/attestation');
  }

  // =========================================================================
  // Manifest Operations
  // =========================================================================

  /**
   * Get a manifest by ID
   *
   * @param id - Manifest identifier
   * @returns Manifest
   */
  async getManifest(id: string): Promise<ApiResponse<GetManifestResponse>> {
    return this.client.get<GetManifestResponse>(
      this.buildUrl(`/manifests/${this.encodePathSegment(id)}`)
    );
  }

  /**
   * Build a new manifest
   *
   * @param request - Build request with configuration
   * @returns Built manifest
   */
  async buildManifest(request: BuildManifestRequest): Promise<ApiResponse<BuildManifestResponse>> {
    return this.client.post<BuildManifestResponse>(this.buildUrl('/manifests'), request);
  }

  /**
   * Verify a manifest
   *
   * @param request - Verification request
   * @returns Verification result
   */
  async verifyManifest(request: VerifyManifestRequest): Promise<ApiResponse<VerifyManifestResponse>> {
    return this.client.post<VerifyManifestResponse>(this.buildUrl('/manifests/verify'), request);
  }

  /**
   * List manifests
   *
   * @param request - List request with filters
   * @returns List of manifests
   */
  async listManifests(request?: ListManifestsRequest): Promise<ApiResponse<ListManifestsResponse>> {
    return this.client.get<ListManifestsResponse>(this.buildUrl('/manifests', {
      limit: request?.limit,
      page: request?.offset !== undefined ? Math.floor(request.offset / (request.limit ?? 10)) + 1 : undefined,
      filters: {
        hostId: request?.hostId,
        startTime: request?.startTime,
        endTime: request?.endTime,
      },
    }));
  }

  /**
   * Delete a manifest
   *
   * @param id - Manifest identifier
   * @returns Deletion result
   */
  async deleteManifest(id: string): Promise<ApiResponse<DeleteManifestResponse>> {
    return this.client.delete<DeleteManifestResponse>(
      this.buildUrl(`/manifests/${this.encodePathSegment(id)}`)
    );
  }

  // =========================================================================
  // Quote Operations
  // =========================================================================

  /**
   * Get an attestation quote
   *
   * @param request - Quote request
   * @returns Attestation quote
   */
  async getQuote(request: GetAttestationQuoteRequest): Promise<ApiResponse<GetAttestationQuoteResponse>> {
    return this.client.post<GetAttestationQuoteResponse>(this.buildUrl('/quote'), request);
  }

  /**
   * Verify an attestation quote
   *
   * @param request - Verification request
   * @returns Verification result
   */
  async verifyQuote(request: VerifyAttestationQuoteRequest): Promise<ApiResponse<VerifyAttestationQuoteResponse>> {
    return this.client.post<VerifyAttestationQuoteResponse>(this.buildUrl('/quote/verify'), request);
  }

  // =========================================================================
  // Collection Operations
  // =========================================================================

  /**
   * Collect host attestation
   *
   * @param request - Collection request
   * @returns Host attestation
   */
  async collectHostAttestation(request: CollectHostAttestationRequest): Promise<ApiResponse<CollectHostAttestationResponse>> {
    return this.client.post<CollectHostAttestationResponse>(this.buildUrl('/collect/host'), request);
  }

  /**
   * Collect VM attestation
   *
   * @param request - Collection request
   * @returns VM attestation
   */
  async collectVMAttestation(request: CollectVMAttestationRequest): Promise<ApiResponse<CollectVMAttestationResponse>> {
    return this.client.post<CollectVMAttestationResponse>(this.buildUrl('/collect/vm'), request);
  }

  /**
   * Collect container attestation
   *
   * @param request - Collection request
   * @returns Container attestation
   */
  async collectContainerAttestation(request: CollectContainerAttestationRequest): Promise<ApiResponse<CollectContainerAttestationResponse>> {
    return this.client.post<CollectContainerAttestationResponse>(this.buildUrl('/collect/container'), request);
  }
}
