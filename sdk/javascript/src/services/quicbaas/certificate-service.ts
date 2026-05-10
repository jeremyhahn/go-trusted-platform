/**
 * QuicBaaS Certificate Service
 *
 * Provides operations for X.509 certificate management including
 * certificate issuance, revocation, renewal, and chain verification.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { Transport } from '../../transport/transport.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  QuicBaaSIssueCertificateRequest,
  QuicBaaSRevokeCertificateRequest,
  QuicBaaSGetCertificateRequest,
  QuicBaaSListCertificatesRequest,
  QuicBaaSRenewCertificateRequest,
  QuicBaaSGetCertificateChainRequest,
  QuicBaaSVerifyCertificateRequest,
  QuicBaaSIssueCertificateResponse,
  QuicBaaSRevokeCertificateResponse,
  QuicBaaSGetCertificateResponse,
  QuicBaaSListCertificatesResponse,
  QuicBaaSRenewCertificateResponse,
  QuicBaaSGetCertificateChainResponse,
  QuicBaaSVerifyCertificateResponse,
} from '../../types/quicbaas/security-part2.js';

/**
 * QuicBaaS Certificate Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Issue a new certificate
 * const cert = await client.quicbaas.certificates.issue({
 *   subject: { commonName: 'my-service.example.com' },
 *   type: 'TLS_SERVER',
 *   keyAlgorithm: 'ECDSA_P256',
 *   validityDays: 365,
 * });
 *
 * // Get certificate chain
 * const chain = await client.quicbaas.certificates.getChain({
 *   certificateId: cert.data.certificate?.certificateId,
 *   includeRoot: true,
 * });
 *
 * // Verify a certificate
 * const verification = await client.quicbaas.certificates.verify({
 *   certificateId: cert.data.certificate?.certificateId,
 *   checkRevocation: true,
 * });
 * ```
 */
export class CertificateService extends BaseService {
  /**
   * Creates a new Certificate service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/quicbaas');
  }

  // =========================================================================
  // Certificate Management
  // =========================================================================

  /**
   * Issue a new X.509 certificate
   *
   * @param request - Certificate issuance request
   * @returns Issued certificate with metadata and optional PEM
   */
  async issue(request: QuicBaaSIssueCertificateRequest): Promise<ApiResponse<QuicBaaSIssueCertificateResponse>> {
    return this.client.post<QuicBaaSIssueCertificateResponse>(
      this.buildUrl('/certificates'),
      request
    );
  }

  /**
   * Revoke an existing certificate
   *
   * @param request - Certificate revocation request
   * @returns Revocation result with new certificate status
   */
  async revoke(request: QuicBaaSRevokeCertificateRequest): Promise<ApiResponse<QuicBaaSRevokeCertificateResponse>> {
    return this.client.post<QuicBaaSRevokeCertificateResponse>(
      this.buildUrl(`/certificates/${this.encodePathSegment(request.certificateId)}/revoke`),
      { reason: request.reason, comment: request.comment }
    );
  }

  /**
   * Get certificate by ID
   *
   * @param certificateId - Certificate identifier
   * @param options - Optional parameters
   * @returns Certificate metadata and optional PEM
   */
  async get(
    certificateId: string,
    options?: Omit<QuicBaaSGetCertificateRequest, 'certificateId'>
  ): Promise<ApiResponse<QuicBaaSGetCertificateResponse>> {
    return this.client.get<QuicBaaSGetCertificateResponse>(
      this.buildUrl(`/certificates/${this.encodePathSegment(certificateId)}`, {
        filters: {
          includePem: options?.includePem?.toString(),
        },
      })
    );
  }

  /**
   * List certificates with optional filtering
   *
   * @param options - List options with filtering
   * @returns List of certificate metadata
   */
  async list(options?: QuicBaaSListCertificatesRequest): Promise<ApiResponse<QuicBaaSListCertificatesResponse>> {
    return this.client.get<QuicBaaSListCertificatesResponse>(
      this.buildUrl('/certificates', {
        limit: options?.limit,
        filters: {
          type: options?.type,
          status: options?.status,
          issuerCertificateId: options?.issuerCertificateId,
          cursor: options?.cursor,
        },
      })
    );
  }

  /**
   * Renew an existing certificate
   *
   * @param request - Certificate renewal request
   * @returns Renewed certificate with metadata and optional PEM
   */
  async renew(request: QuicBaaSRenewCertificateRequest): Promise<ApiResponse<QuicBaaSRenewCertificateResponse>> {
    return this.client.post<QuicBaaSRenewCertificateResponse>(
      this.buildUrl(`/certificates/${this.encodePathSegment(request.certificateId)}/renew`),
      { validityDays: request.validityDays, reuseKey: request.reuseKey }
    );
  }

  /**
   * Get certificate chain for a certificate
   *
   * @param request - Get chain request
   * @returns Certificate chain from leaf to root
   */
  async getChain(request: QuicBaaSGetCertificateChainRequest): Promise<ApiResponse<QuicBaaSGetCertificateChainResponse>> {
    return this.client.get<QuicBaaSGetCertificateChainResponse>(
      this.buildUrl(`/certificates/${this.encodePathSegment(request.certificateId)}/chain`, {
        filters: {
          includeIntermediates: request.includeIntermediates?.toString(),
          includeRoot: request.includeRoot?.toString(),
        },
      })
    );
  }

  /**
   * Verify a certificate
   *
   * @param request - Certificate verification request
   * @returns Verification result with validation details
   */
  async verify(request: QuicBaaSVerifyCertificateRequest): Promise<ApiResponse<QuicBaaSVerifyCertificateResponse>> {
    return this.client.post<QuicBaaSVerifyCertificateResponse>(
      this.buildUrl('/certificates/verify'),
      request
    );
  }
}
