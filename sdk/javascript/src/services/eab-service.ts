/**
 * EAB (External Account Binding) Service
 *
 * Provides operations for EAB credential management including creating,
 * listing, revoking, and validating EAB credentials for ACME enrollment.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  CreateEABCredentialRequest,
  CreateEABCredentialResponse,
  GetEABCredentialResponse,
  GetEABCredentialByKeyIdResponse,
  ListEABCredentialsRequest,
  ListEABCredentialsResponse,
  RevokeEABCredentialResponse,
  ValidateEABCredentialRequest,
  ValidateEABCredentialResponse,
  DeleteEABCredentialResponse,
  GetEABQRCodeResponse,
  GetEnrollmentURLResponse,
  MarkEABCredentialUsedResponse,
  CleanupExpiredEABCredentialsRequest,
  CleanupExpiredEABCredentialsResponse,
} from '../types/eab.js';

/**
 * EAB Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create an EAB credential
 * const credential = await client.eab.create({
 *   profileId: 1,
 *   tenantId: 'tenant-123',
 *   expiresInSeconds: 86400, // 24 hours
 * });
 *
 * // Validate a credential
 * const validation = await client.eab.validate({
 *   keyId: credential.data.credential?.keyId ?? '',
 *   hmacKey: credential.data.credential?.hmacKey ?? '',
 * });
 *
 * // List credentials for a tenant
 * const credentials = await client.eab.list({
 *   tenantId: 'tenant-123',
 *   status: 'ACTIVE',
 * });
 * ```
 */
export class EABService extends BaseService {
  /**
   * Creates a new EAB service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/eab');
  }

  // =========================================================================
  // EAB CRUD Operations
  // =========================================================================

  /**
   * Create an EAB credential
   *
   * @param request - Credential creation request
   * @returns Created credential with HMAC key
   */
  async create(request: CreateEABCredentialRequest): Promise<ApiResponse<CreateEABCredentialResponse>> {
    return this.client.post<CreateEABCredentialResponse>(this.buildUrl('/credentials'), request);
  }

  /**
   * Get an EAB credential by ID
   *
   * @param id - Credential ID
   * @returns Credential information (without HMAC key)
   */
  async get(id: number): Promise<ApiResponse<GetEABCredentialResponse>> {
    return this.client.get<GetEABCredentialResponse>(
      this.buildUrl(`/credentials/${id}`)
    );
  }

  /**
   * Get an EAB credential by key ID
   *
   * @param keyId - Key identifier
   * @returns Credential information (without HMAC key)
   */
  async getByKeyId(keyId: string): Promise<ApiResponse<GetEABCredentialByKeyIdResponse>> {
    return this.client.get<GetEABCredentialByKeyIdResponse>(
      this.buildUrl(`/credentials/key/${this.encodePathSegment(keyId)}`)
    );
  }

  /**
   * List EAB credentials
   *
   * @param request - List request with filters
   * @returns List of credentials
   */
  async list(request?: ListEABCredentialsRequest): Promise<ApiResponse<ListEABCredentialsResponse>> {
    // Query names and status values as ListCredentials reads them
    // (pkg/webservice/v1/rest/eab/handlers.go listCredentialsRequestFromQuery).
    const filters: Record<string, string | number | boolean | undefined> = {};
    if (request?.profileId !== undefined) {
      filters.profile_id = request.profileId;
    }
    if (request?.tenantId !== undefined) {
      filters.tenant_id = request.tenantId;
    }
    if (request?.status !== undefined) {
      filters.status = `EAB_CREDENTIAL_STATUS_${request.status}`;
    }
    if (request?.pageSize !== undefined) {
      filters.page_size = request.pageSize;
    }
    return this.client.get<ListEABCredentialsResponse>(this.buildUrl('/credentials', {
      page: request?.page,
      filters,
    }));
  }

  /**
   * Revoke an EAB credential
   *
   * @param id - Credential ID
   * @returns Revocation result
   */
  async revoke(id: number): Promise<ApiResponse<RevokeEABCredentialResponse>> {
    return this.client.post<RevokeEABCredentialResponse>(
      this.buildUrl(`/credentials/${id}/revoke`),
      {}
    );
  }

  /**
   * Validate an EAB credential
   *
   * @param request - Validation request with keyId and hmacKey
   * @returns Validation result
   */
  async validate(request: ValidateEABCredentialRequest): Promise<ApiResponse<ValidateEABCredentialResponse>> {
    return this.client.post<ValidateEABCredentialResponse>(
      this.buildUrl('/credentials/validate'),
      request
    );
  }

  /**
   * Delete an EAB credential
   *
   * @param id - Credential ID
   * @returns Deletion result
   */
  async delete(id: number): Promise<ApiResponse<DeleteEABCredentialResponse>> {
    return this.client.delete<DeleteEABCredentialResponse>(
      this.buildUrl(`/credentials/${id}`)
    );
  }

  // =========================================================================
  // Enrollment Operations
  // =========================================================================

  /**
   * Get QR code for an EAB credential (GET /credentials/{id}/qrcode)
   *
   * The server reads `size` as an unsigned integer and answers 400 to a
   * fraction, so a fractional size is floored and a negative or non-finite
   * size is left out (the server then uses its default of 256 pixels).
   *
   * @param id - Credential ID
   * @param size - QR code size in pixels (optional, integer)
   * @returns The base64-encoded PNG and its content type
   */
  async getQRCode(id: number, size?: number): Promise<ApiResponse<GetEABQRCodeResponse>> {
    const filters: Record<string, string | number | boolean | undefined> = {};
    if (size !== undefined && Number.isFinite(size) && size >= 0) {
      filters.size = Math.floor(size);
    }
    return this.client.get<GetEABQRCodeResponse>(
      this.buildUrl(`/credentials/${id}/qrcode`, { filters })
    );
  }

  /**
   * Get enrollment URL for an EAB credential
   *
   * Calls GET /v1/eab/credentials/{id}/url.
   *
   * @param id - Credential ID
   * @param path - Enrolment path to append to the URL (optional)
   * @returns Enrollment URL with expiration
   */
  async getEnrollmentURL(id: number, path?: string): Promise<ApiResponse<GetEnrollmentURLResponse>> {
    return this.client.get<GetEnrollmentURLResponse>(
      this.buildUrl(`/credentials/${id}/url`, path ? { filters: { path } } : undefined)
    );
  }

  /**
   * Mark an EAB credential as used
   *
   * Calls POST /v1/eab/credentials/{id}/used.
   *
   * @param id - Credential ID
   * @returns Operation status
   */
  async markUsed(id: number): Promise<ApiResponse<MarkEABCredentialUsedResponse>> {
    return this.client.post<MarkEABCredentialUsedResponse>(
      this.buildUrl(`/credentials/${id}/used`),
      {}
    );
  }

  /**
   * Delete expired EAB credentials
   *
   * Calls POST /v1/eab/credentials/cleanup.
   *
   * @param tenantId - Restrict the cleanup to one tenant (optional)
   * @returns Number of credentials deleted
   */
  async cleanupExpired(tenantId?: string): Promise<ApiResponse<CleanupExpiredEABCredentialsResponse>> {
    const body: CleanupExpiredEABCredentialsRequest = tenantId ? { tenantId } : {};
    return this.client.post<CleanupExpiredEABCredentialsResponse>(
      this.buildUrl('/credentials/cleanup'),
      body
    );
  }
}
