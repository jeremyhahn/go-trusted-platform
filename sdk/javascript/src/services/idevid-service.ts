/**
 * IDevID (Device Identity) Service
 *
 * Provides operations for device identity management including IDevID and IAK.
 */

import type { ApiClient } from '../client/api-client.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  GenerateIDevIDRequest,
  GenerateIDevIDResponse,
  GetIDevIDInfoResponse,
  HasIDevIDResponse,
  DeleteIDevIDResponse,
  GenerateIAKRequest,
  GenerateIAKResponse,
  GetIAKInfoResponse,
  HasIAKResponse,
  DeleteIAKResponse,
  CreateIDevIDCSRRequest,
  CreateIDevIDCSRResponse,
  CreateIAKCSRRequest,
  CreateIAKCSRResponse,
  InstallIDevIDCertificateRequest,
  InstallIDevIDCertificateResponse,
  InstallIAKCertificateRequest,
  InstallIAKCertificateResponse,
  GetIDevIDCertificateResponse,
  GetIAKCertificateResponse,
  DeleteIDevIDCertificateResponse,
  DeleteIAKCertificateResponse,
  GetDeviceAttributesResponse,
  FlushTransientContextsResponse,
  ActivateCredentialRequest,
  ActivateCredentialResponse,
} from '../types/idevid.js';

/**
 * IDevID Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Generate IDevID
 * const result = await client.idevid.generateIDevID({
 *   config: {
 *     algorithm: 'ECDSA_P256',
 *     hierarchy: 'endorsement',
 *   }
 * });
 *
 * // Create CSR for IDevID
 * const csr = await client.idevid.createIDevIDCSR({
 *   template: {
 *     commonName: 'device-001',
 *     organization: 'My Corp',
 *   }
 * });
 * ```
 */
export class IDevIDService extends BaseService {
  /**
   * Creates a new IDevID service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/idevid');
  }

  // =========================================================================
  // IDevID Operations
  // =========================================================================

  /**
   * Generate IDevID key pair
   *
   * @param request - Generation request
   * @returns Generation result
   */
  async generateIDevID(request?: GenerateIDevIDRequest): Promise<ApiResponse<GenerateIDevIDResponse>> {
    return this.client.post<GenerateIDevIDResponse>(this.buildUrl('/generate'), request ?? {});
  }

  /**
   * Get IDevID information
   *
   * @returns IDevID key information
   */
  async getIDevIDInfo(): Promise<ApiResponse<GetIDevIDInfoResponse>> {
    return this.client.get<GetIDevIDInfoResponse>(this.buildUrl('/info'));
  }

  /**
   * Check if IDevID exists
   *
   * @returns Whether IDevID exists
   */
  async hasIDevID(): Promise<ApiResponse<HasIDevIDResponse>> {
    return this.client.get<HasIDevIDResponse>(this.buildUrl('/exists'));
  }

  /**
   * Delete IDevID
   *
   * @returns Deletion result
   */
  async deleteIDevID(): Promise<ApiResponse<DeleteIDevIDResponse>> {
    return this.client.delete<DeleteIDevIDResponse>(this.buildUrl(''));
  }

  /**
   * Create CSR for IDevID
   *
   * @param request - CSR template
   * @returns CSR in PEM format
   */
  async createIDevIDCSR(request?: CreateIDevIDCSRRequest): Promise<ApiResponse<CreateIDevIDCSRResponse>> {
    return this.client.post<CreateIDevIDCSRResponse>(this.buildUrl('/csr'), request ?? {});
  }

  /**
   * Install IDevID certificate
   *
   * @param request - Certificate installation request
   * @returns Installation result
   */
  async installIDevIDCertificate(request: InstallIDevIDCertificateRequest): Promise<ApiResponse<InstallIDevIDCertificateResponse>> {
    return this.client.post<InstallIDevIDCertificateResponse>(this.buildUrl('/certificate'), request);
  }

  /**
   * Get IDevID certificate
   *
   * @returns IDevID certificate
   */
  async getIDevIDCertificate(): Promise<ApiResponse<GetIDevIDCertificateResponse>> {
    return this.client.get<GetIDevIDCertificateResponse>(this.buildUrl('/certificate'));
  }

  /**
   * Delete IDevID certificate
   *
   * @returns Deletion result
   */
  async deleteIDevIDCertificate(): Promise<ApiResponse<DeleteIDevIDCertificateResponse>> {
    return this.client.delete<DeleteIDevIDCertificateResponse>(this.buildUrl('/certificate'));
  }

  // =========================================================================
  // IAK Operations
  // =========================================================================

  /**
   * Generate IAK key pair
   *
   * @param request - Generation request
   * @returns Generation result
   */
  async generateIAK(request?: GenerateIAKRequest): Promise<ApiResponse<GenerateIAKResponse>> {
    return this.client.post<GenerateIAKResponse>(this.buildUrl('/iak/generate'), request ?? {});
  }

  /**
   * Get IAK information
   *
   * @returns IAK key information
   */
  async getIAKInfo(): Promise<ApiResponse<GetIAKInfoResponse>> {
    return this.client.get<GetIAKInfoResponse>(this.buildUrl('/iak/info'));
  }

  /**
   * Check if IAK exists
   *
   * @returns Whether IAK exists
   */
  async hasIAK(): Promise<ApiResponse<HasIAKResponse>> {
    return this.client.get<HasIAKResponse>(this.buildUrl('/iak/exists'));
  }

  /**
   * Delete IAK
   *
   * @returns Deletion result
   */
  async deleteIAK(): Promise<ApiResponse<DeleteIAKResponse>> {
    return this.client.delete<DeleteIAKResponse>(this.buildUrl('/iak'));
  }

  /**
   * Create CSR for IAK
   *
   * @param request - CSR template
   * @returns CSR in PEM format
   */
  async createIAKCSR(request?: CreateIAKCSRRequest): Promise<ApiResponse<CreateIAKCSRResponse>> {
    return this.client.post<CreateIAKCSRResponse>(this.buildUrl('/iak/csr'), request ?? {});
  }

  /**
   * Install IAK certificate
   *
   * @param request - Certificate installation request
   * @returns Installation result
   */
  async installIAKCertificate(request: InstallIAKCertificateRequest): Promise<ApiResponse<InstallIAKCertificateResponse>> {
    return this.client.post<InstallIAKCertificateResponse>(this.buildUrl('/iak/certificate'), request);
  }

  /**
   * Get IAK certificate
   *
   * @returns IAK certificate
   */
  async getIAKCertificate(): Promise<ApiResponse<GetIAKCertificateResponse>> {
    return this.client.get<GetIAKCertificateResponse>(this.buildUrl('/iak/certificate'));
  }

  /**
   * Delete IAK certificate
   *
   * @returns Deletion result
   */
  async deleteIAKCertificate(): Promise<ApiResponse<DeleteIAKCertificateResponse>> {
    return this.client.delete<DeleteIAKCertificateResponse>(this.buildUrl('/iak/certificate'));
  }

  // =========================================================================
  // Device Attributes and Utilities
  // =========================================================================

  /**
   * Get TCG device attributes
   *
   * @returns Device attributes
   */
  async getDeviceAttributes(): Promise<ApiResponse<GetDeviceAttributesResponse>> {
    return this.client.get<GetDeviceAttributesResponse>(this.buildUrl('/attributes'));
  }

  /**
   * Flush transient TPM contexts
   *
   * @returns Flush result
   */
  async flushTransientContexts(): Promise<ApiResponse<FlushTransientContextsResponse>> {
    return this.client.post<FlushTransientContextsResponse>(this.buildUrl('/flush'), {});
  }

  /**
   * Activate credential (for enrollment)
   *
   * @param request - Activation request
   * @returns Decrypted secret
   */
  async activateCredential(request: ActivateCredentialRequest): Promise<ApiResponse<ActivateCredentialResponse>> {
    return this.client.post<ActivateCredentialResponse>(this.buildUrl('/activate-credential'), request);
  }
}
