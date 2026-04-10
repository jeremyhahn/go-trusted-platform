/**
 * EAB (External Account Binding) Service
 *
 * Provides operations for EAB credential management including creating,
 * listing, revoking, and validating EAB credentials for ACME enrollment.
 */

import type { ApiClient } from '../client/api-client.js';
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
  constructor(client: ApiClient) {
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
    const filters: Record<string, string | number | boolean | undefined> = {};
    if (request?.profileId !== undefined) {
      filters.profileId = request.profileId;
    }
    if (request?.tenantId !== undefined) {
      filters.tenantId = request.tenantId;
    }
    if (request?.status !== undefined) {
      filters.status = request.status;
    }
    return this.client.get<ListEABCredentialsResponse>(this.buildUrl('/credentials', {
      page: request?.page,
      limit: request?.pageSize,
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
   * Get QR code for an EAB credential
   *
   * @param id - Credential ID
   * @param size - QR code size in pixels (optional)
   * @returns Base64-encoded QR code image
   */
  async getQRCode(id: number, size?: number): Promise<ApiResponse<GetEABQRCodeResponse>> {
    const filters: Record<string, string | number | boolean | undefined> = {};
    if (size !== undefined) {
      filters.size = size;
    }
    return this.client.get<GetEABQRCodeResponse>(
      this.buildUrl(`/credentials/${id}/qrcode`, { filters })
    );
  }

  /**
   * Get enrollment URL for an EAB credential
   *
   * @param id - Credential ID
   * @returns Enrollment URL with expiration
   */
  async getEnrollmentURL(id: number): Promise<ApiResponse<GetEnrollmentURLResponse>> {
    return this.client.get<GetEnrollmentURLResponse>(
      this.buildUrl(`/credentials/${id}/enrollment-url`)
    );
  }
}
