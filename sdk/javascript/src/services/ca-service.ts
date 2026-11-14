/**
 * Certificate Authority Service
 *
 * Provides operations for certificate management including issuance, revocation,
 * renewal, and CRL management.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService, type ListOptions } from './base-service.js';
import type {
  Certificate,
  CertificateSummary,
  CertificateRequest,
  RevokeCertificateRequest,
  RenewCertificateRequest,
  VerifyCertificateRequest,
  GetCAInfoResponse,
  IssueCertificateResponse,
  GetCertificateResponse,
  ListCertificatesResponse,
  RevokeCertificateResponse,
  RenewCertificateResponse,
  VerifyCertificateResponse,
  GetCRLResponse,
  GetCABundleResponse,
} from '../types/ca.js';
import {
  CERTIFICATE_TYPE_PROTO_NAMES,
  KEY_ALGORITHM_PROTO_NAMES,
  REVOCATION_REASON_PROTO_NAMES,
} from '../types/ca.js';
import { encodeEnum } from './wire-enum.js';

/**
 * The protojson body of a platform.v1.CertificateRequest. The REST decoder
 * is protojson: enums travel as their full protobuf names and `is_ca` as
 * `isCa`; anything else is discarded as unknown.
 */
function toWireCertificateRequest(request: CertificateRequest): Record<string, unknown> {
  const { keyAlgorithm, certificateType, isCA, ...rest } = request;
  const wire: Record<string, unknown> = { ...rest };
  if (keyAlgorithm !== undefined) {
    wire.keyAlgorithm = encodeEnum('keyAlgorithm', KEY_ALGORITHM_PROTO_NAMES, keyAlgorithm);
  }
  if (certificateType !== undefined) {
    wire.certificateType = encodeEnum('certificateType', CERTIFICATE_TYPE_PROTO_NAMES, certificateType);
  }
  if (isCA !== undefined) {
    wire.isCa = isCA;
  }
  return wire;
}

/**
 * Certificate Authority Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Get CA info
 * const info = await client.ca.getInfo();
 *
 * // Issue a certificate
 * const cert = await client.ca.issueCertificate({
 *   subject: { commonName: 'example.com' },
 *   validDays: 365,
 * });
 *
 * // Revoke a certificate
 * await client.ca.revokeCertificate({
 *   serial: cert.data.certificate.serial,
 *   reason: 'KEY_COMPROMISE',
 * });
 * ```
 */
export class CAService extends BaseService {
  /**
   * Creates a new CA service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/ca');
  }

  /**
   * Get CA information
   *
   * @returns CA information including root cert and intermediate certs
   */
  async getInfo(): Promise<ApiResponse<GetCAInfoResponse>> {
    return this.client.get<GetCAInfoResponse>(this.buildUrl('/info'));
  }

  /**
   * Get CA root certificate
   *
   * @returns CA root certificate
   */
  async getRootCertificate(): Promise<ApiResponse<Certificate>> {
    return this.client.get<Certificate>(this.buildUrl('/root'));
  }

  /**
   * List all certificates
   *
   * @param options - Pagination and filter options
   * @returns List of certificate summaries
   */
  async listCertificates(options?: ListOptions): Promise<ApiResponse<ListCertificatesResponse>> {
    return this.client.get<ListCertificatesResponse>(this.buildUrl('/certificates', options));
  }

  /**
   * Get certificate by serial number
   *
   * @param serial - Certificate serial number (hex)
   * @returns Certificate details
   */
  async getCertificate(serial: string): Promise<ApiResponse<GetCertificateResponse>> {
    return this.client.get<GetCertificateResponse>(
      this.buildUrl(`/certificates/${this.encodePathSegment(serial)}`)
    );
  }

  /**
   * Issue a new certificate
   *
   * @param request - Certificate request with subject and configuration
   * @returns Issued certificate
   */
  async issueCertificate(request: CertificateRequest): Promise<ApiResponse<IssueCertificateResponse>> {
    return this.client.post<IssueCertificateResponse>(this.buildUrl('/certificates'), {
      request: toWireCertificateRequest(request),
    });
  }

  /**
   * Revoke a certificate
   *
   * @param request - Revocation request with serial and reason
   * @returns Revocation result
   */
  async revokeCertificate(request: RevokeCertificateRequest): Promise<ApiResponse<RevokeCertificateResponse>> {
    // The router serves revocation as DELETE /certificates/{serial} and reads
    // the reason and deleteKeys from the request body.
    return this.client.delete<RevokeCertificateResponse>(
      this.buildUrl(`/certificates/${this.encodePathSegment(request.serial)}`),
      undefined,
      { reason: encodeEnum('reason', REVOCATION_REASON_PROTO_NAMES, request.reason), deleteKeys: request.deleteKeys }
    );
  }

  /**
   * Renew a certificate
   *
   * @param request - Renewal request with serial and options
   * @returns Renewed certificate
   */
  async renewCertificate(request: RenewCertificateRequest): Promise<ApiResponse<RenewCertificateResponse>> {
    return this.client.post<RenewCertificateResponse>(
      this.buildUrl(`/certificates/${this.encodePathSegment(request.serial)}/renew`),
      { validDays: request.validDays, preserveSans: request.preserveSans, newSans: request.newSans }
    );
  }

  /**
   * Verify a certificate
   *
   * @param request - Verification request with certificate and options
   * @returns Verification result
   */
  async verifyCertificate(request: VerifyCertificateRequest): Promise<ApiResponse<VerifyCertificateResponse>> {
    return this.client.post<VerifyCertificateResponse>(this.buildUrl('/certificates/verify'), request);
  }

  /**
   * Get Certificate Revocation List (CRL)
   *
   * @returns CRL data
   */
  async getCRL(): Promise<ApiResponse<GetCRLResponse>> {
    return this.client.get<GetCRLResponse>(this.buildUrl('/crl'));
  }

  /**
   * Download CRL in binary format
   *
   * @returns CRL binary data
   */
  async downloadCRL(): Promise<ApiResponse<ArrayBuffer>> {
    return this.client.get<ArrayBuffer>(this.buildUrl('/crl/download'), {
      headers: { Accept: 'application/pkix-crl' },
    });
  }

  /**
   * Get CA certificate bundle
   *
   * @returns CA bundle with all certificates in chain
   */
  async getBundle(): Promise<ApiResponse<GetCABundleResponse>> {
    return this.client.get<GetCABundleResponse>(this.buildUrl('/bundle'));
  }

  /**
   * Download CA bundle in PEM format
   *
   * @returns PEM-encoded bundle
   */
  async downloadBundle(): Promise<ApiResponse<string>> {
    return this.client.get<string>(this.buildUrl('/bundle/download'), {
      headers: { Accept: 'application/x-pem-file' },
    });
  }

  /**
   * Download certificate in PEM format
   *
   * @param serial - Certificate serial number
   * @returns PEM-encoded certificate
   */
  async downloadCertificatePEM(serial: string): Promise<ApiResponse<string>> {
    return this.client.get<string>(
      this.buildUrl(`/certificates/${this.encodePathSegment(serial)}/download`),
      { headers: { Accept: 'application/x-pem-file' } }
    );
  }

  /**
   * Download certificate in DER format
   *
   * @param serial - Certificate serial number
   * @returns DER-encoded certificate
   */
  async downloadCertificateDER(serial: string): Promise<ApiResponse<ArrayBuffer>> {
    return this.client.get<ArrayBuffer>(
      this.buildUrl(`/certificates/${this.encodePathSegment(serial)}/download`),
      { headers: { Accept: 'application/x-x509-ca-cert' } }
    );
  }

  /**
   * Get certificate chain for a certificate
   *
   * @param serial - Certificate serial number
   * @returns Certificate chain
   */
  async getCertificateChain(serial: string): Promise<ApiResponse<CertificateSummary[]>> {
    return this.client.get<CertificateSummary[]>(
      this.buildUrl(`/certificates/${this.encodePathSegment(serial)}/chain`)
    );
  }

  /**
   * Check if a certificate is revoked
   *
   * @param serial - Certificate serial number
   * @returns Revocation status
   */
  async isRevoked(serial: string): Promise<ApiResponse<{ revoked: boolean; reason?: string; revokedAt?: string }>> {
    return this.client.get<{ revoked: boolean; reason?: string; revokedAt?: string }>(
      this.buildUrl(`/certificates/${this.encodePathSegment(serial)}/status`)
    );
  }
}
