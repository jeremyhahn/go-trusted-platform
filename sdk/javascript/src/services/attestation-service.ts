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
  DeviceReport,
  ListDeviceReportsResponse,
  RefreshDeviceReportResponse,
  CallerPolicyDescription,
  AttestationHashAlgorithm,
  AttestationHashAlgorithmProtoName,
  AttestationPCRValue,
} from '../types/attestation.js';
import { ATTESTATION_HASH_ALGORITHM_PROTO_NAMES } from '../types/attestation.js';

/**
 * Replaces a config's short hash algorithm with its proto name. The REST
 * decoder is protojson, which discards the short name.
 */
function withWireHashAlgorithm<T extends { hashAlgorithm?: AttestationHashAlgorithm }>(
  config: T,
): Omit<T, 'hashAlgorithm'> & { hashAlgorithm?: AttestationHashAlgorithmProtoName } {
  const { hashAlgorithm, ...rest } = config;
  if (hashAlgorithm === undefined) {
    return rest;
  }
  return { ...rest, hashAlgorithm: ATTESTATION_HASH_ALGORITHM_PROTO_NAMES[hashAlgorithm] };
}

/** Replaces a request's config with its wire form, when the request has one. */
function withWireConfig<T extends { config?: { hashAlgorithm?: AttestationHashAlgorithm } }>(request: T) {
  if (request.config === undefined) {
    return request;
  }
  return { ...request, config: withWireHashAlgorithm(request.config) };
}

function toWirePCRValue(
  pcr: AttestationPCRValue,
): Omit<AttestationPCRValue, 'algorithm'> & { algorithm: AttestationHashAlgorithmProtoName } {
  return { ...pcr, algorithm: ATTESTATION_HASH_ALGORITHM_PROTO_NAMES[pcr.algorithm] };
}

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
    return this.client.post<BuildManifestResponse>(this.buildUrl('/manifests/build'), withWireConfig(request));
  }

  /**
   * Verify a manifest
   *
   * @param request - Verification request
   * @returns Verification result
   */
  async verifyManifest(request: VerifyManifestRequest): Promise<ApiResponse<VerifyManifestResponse>> {
    return this.client.post<VerifyManifestResponse>(this.buildUrl('/manifests/verify'), withWireConfig(request));
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
    return this.client.post<GetAttestationQuoteResponse>(this.buildUrl('/quote'), withWireConfig(request));
  }

  /**
   * Verify an attestation quote
   *
   * @param request - Verification request
   * @returns Verification result
   */
  async verifyQuote(request: VerifyAttestationQuoteRequest): Promise<ApiResponse<VerifyAttestationQuoteResponse>> {
    const { expectedPcrs, ...rest } = request;
    return this.client.post<VerifyAttestationQuoteResponse>(this.buildUrl('/quote/verify'), {
      ...rest,
      ...(expectedPcrs !== undefined && { expectedPcrs: expectedPcrs.map(toWirePCRValue) }),
    });
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
  // ---------------------------------------------------------------------------
  // Device reports — the collector's cached verdicts (#226, #428)
  // ---------------------------------------------------------------------------

  /**
   * Every cached device report, each with its age.
   *
   * `GET /api/v1/attestation/reports`. Admin-gated. A 503 means the
   * reporting service is not configured on this node.
   */
  async listDeviceReports(): Promise<ApiResponse<ListDeviceReportsResponse>> {
    return this.client.get<ListDeviceReportsResponse>(this.buildUrl('/reports'));
  }

  /**
   * One device's cached report with its age.
   *
   * `GET /api/v1/attestation/reports/{device_id}`. A 404 is "never
   * collected" and is not a failed verdict; classify the response with
   * {@link classifyDeviceReport} rather than reading `success` alone.
   */
  async getDeviceReport(deviceId: string): Promise<ApiResponse<DeviceReport>> {
    return this.client.get<DeviceReport>(
      this.buildUrl(`/reports/${this.encodePathSegment(deviceId)}`)
    );
  }

  /**
   * Enqueue an out-of-cycle collection for a device.
   *
   * `POST /api/v1/attestation/reports/{device_id}/refresh` answers 202 with
   * `enqueued: true` and never a quote; read the report again for the new
   * verdict and its age. Repeated refreshes coalesce into one collection.
   */
  async refreshDeviceReport(deviceId: string): Promise<ApiResponse<RefreshDeviceReportResponse>> {
    return this.client.post<RefreshDeviceReportResponse>(
      this.buildUrl(`/reports/${this.encodePathSegment(deviceId)}/refresh`),
      {}
    );
  }

  /**
   * Which machine callers this node admits to its quote-producing routes.
   *
   * `GET /api/v1/attestation/callers`.
   */
  async describeCallers(): Promise<ApiResponse<CallerPolicyDescription>> {
    return this.client.get<CallerPolicyDescription>(this.buildUrl('/callers'));
  }

  async collectHostAttestation(request: CollectHostAttestationRequest): Promise<ApiResponse<CollectHostAttestationResponse>> {
    return this.client.post<CollectHostAttestationResponse>(this.buildUrl('/host'), withWireConfig(request));
  }

  /**
   * Collect VM attestation
   *
   * @param request - Collection request
   * @returns VM attestation
   */
  async collectVMAttestation(request: CollectVMAttestationRequest): Promise<ApiResponse<CollectVMAttestationResponse>> {
    return this.client.post<CollectVMAttestationResponse>(
      this.buildUrl(`/vm/${this.encodePathSegment(request.vmId)}`),
      withWireConfig(request)
    );
  }

  /**
   * Collect container attestation
   *
   * @param request - Collection request
   * @returns Container attestation
   */
  async collectContainerAttestation(request: CollectContainerAttestationRequest): Promise<ApiResponse<CollectContainerAttestationResponse>> {
    return this.client.post<CollectContainerAttestationResponse>(
      this.buildUrl(`/container/${this.encodePathSegment(request.containerId)}`),
      request
    );
  }
}
