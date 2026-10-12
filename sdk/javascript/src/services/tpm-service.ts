/**
 * TPM (Trusted Platform Module) Service
 *
 * Provides operations for TPM key management, sealing/unsealing, quotes, and NVRAM.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  TPMProvisionRequest,
  TPMClearRequest,
  CreateEKRequest,
  GetEKRequest,
  GetEKCertificateRequest,
  ImportEKCertificateRequest,
  DeleteEKRequest,
  CreateSRKRequest,
  GetSRKRequest,
  DeleteSRKRequest,
  CreateAKRequest,
  GetAKRequest,
  DeleteAKRequest,
  SealRequest,
  UnsealRequest,
  QuoteRequest,
  VerifyQuoteRequest,
  GetEventLogRequest,
  GetPCRsRequest,
  DefineNVRAMRequest,
  WriteNVRAMRequest,
  ReadNVRAMRequest,
  UndefineNVRAMRequest,
  GetRandomRequest,
  TPMInfoResponse,
  TPMProvisionResponse,
  TPMClearResponse,
  CreateEKResponse,
  GetEKResponse,
  GetEKCertificateResponse,
  ImportEKCertificateResponse,
  DeleteEKResponse,
  CreateSRKResponse,
  GetSRKResponse,
  DeleteSRKResponse,
  CreateAKResponse,
  GetAKResponse,
  DeleteAKResponse,
  SealResponse,
  UnsealResponse,
  QuoteResponse,
  VerifyQuoteResponse,
  GetEventLogResponse,
  GetPCRsResponse,
  DefineNVRAMResponse,
  WriteNVRAMResponse,
  ReadNVRAMResponse,
  UndefineNVRAMResponse,
  GetRandomResponse,
} from '../types/tpm.js';

/** Base path of the TPM REST API, under the client's `/api` base URL. */
export const TPM_BASE_PATH = '/v1/tpm';

/**
 * TPM Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Get TPM info
 * const info = await client.tpm.getInfo();
 *
 * // Seal data to PCRs
 * const sealed = await client.tpm.seal({
 *   data: btoa('secret data'),
 *   cn: 'my-sealed-secret',
 *   pcrIndices: [0, 1, 7],
 * });
 * ```
 */
export class TPMService extends BaseService {
  /**
   * Creates a new TPM service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, TPM_BASE_PATH);
  }

  // =========================================================================
  // TPM Information
  // =========================================================================

  /**
   * Get TPM information
   *
   * @returns TPM information
   */
  async getInfo(): Promise<ApiResponse<TPMInfoResponse>> {
    return this.client.get<TPMInfoResponse>(this.buildUrl('/info'));
  }

  /**
   * Provision the TPM
   *
   * @param request - Provisioning request
   * @returns Provisioning result
   */
  async provision(request: TPMProvisionRequest): Promise<ApiResponse<TPMProvisionResponse>> {
    return this.client.post<TPMProvisionResponse>(this.buildUrl('/provision'), request);
  }

  /**
   * Clear the TPM (WARNING: destroys all keys)
   *
   * @param request - Clear request with confirmation
   * @returns Clear result
   */
  async clear(request: TPMClearRequest): Promise<ApiResponse<TPMClearResponse>> {
    return this.client.post<TPMClearResponse>(this.buildUrl('/clear'), request);
  }

  // =========================================================================
  // Endorsement Key (EK) Operations
  // =========================================================================

  /**
   * Create Endorsement Key
   *
   * @param request - EK creation request
   * @returns Created EK
   */
  async createEK(request?: CreateEKRequest): Promise<ApiResponse<CreateEKResponse>> {
    return this.client.post<CreateEKResponse>(this.buildUrl('/ek'), request ?? {});
  }

  /**
   * Get Endorsement Key
   *
   * @param request - Optional filter parameters
   * @returns EK information
   */
  async getEK(request?: GetEKRequest): Promise<ApiResponse<GetEKResponse>> {
    return this.client.get<GetEKResponse>(this.buildUrl('/ek', {
      filters: { algorithm: request?.algorithm, handle: request?.handle?.toString() },
    }));
  }

  /**
   * Get EK certificate
   *
   * @param request - Optional filter parameters
   * @returns EK certificate
   */
  async getEKCertificate(request?: GetEKCertificateRequest): Promise<ApiResponse<GetEKCertificateResponse>> {
    return this.client.get<GetEKCertificateResponse>(this.buildUrl('/ek/certificate', {
      filters: { algorithm: request?.algorithm, handle: request?.handle?.toString() },
    }));
  }

  /**
   * Import EK certificate
   *
   * @param request - Import request
   * @returns Import result
   */
  async importEKCertificate(request: ImportEKCertificateRequest): Promise<ApiResponse<ImportEKCertificateResponse>> {
    return this.client.post<ImportEKCertificateResponse>(this.buildUrl('/ek/certificate'), request);
  }

  /**
   * Delete EK
   *
   * @param request - Delete request
   * @returns Delete result
   */
  async deleteEK(request: DeleteEKRequest): Promise<ApiResponse<DeleteEKResponse>> {
    return this.client.delete<DeleteEKResponse>(this.buildUrl(`/ek/${request.handle}`));
  }

  // =========================================================================
  // Storage Root Key (SRK) Operations
  // =========================================================================

  /**
   * Create Storage Root Key
   *
   * @param request - SRK creation request
   * @returns Created SRK
   */
  async createSRK(request?: CreateSRKRequest): Promise<ApiResponse<CreateSRKResponse>> {
    return this.client.post<CreateSRKResponse>(this.buildUrl('/srk'), request ?? {});
  }

  /**
   * Get Storage Root Key
   *
   * @param request - Optional filter parameters
   * @returns SRK information
   */
  async getSRK(request?: GetSRKRequest): Promise<ApiResponse<GetSRKResponse>> {
    return this.client.get<GetSRKResponse>(this.buildUrl('/srk', {
      filters: { algorithm: request?.algorithm, handle: request?.handle?.toString() },
    }));
  }

  /**
   * Delete SRK
   *
   * @param request - Delete request
   * @returns Delete result
   */
  async deleteSRK(request: DeleteSRKRequest): Promise<ApiResponse<DeleteSRKResponse>> {
    return this.client.delete<DeleteSRKResponse>(this.buildUrl(`/srk/${request.handle}`));
  }

  // =========================================================================
  // Attestation Key (AK) Operations
  // =========================================================================

  /**
   * Create Attestation Key
   *
   * @param request - AK creation request
   * @returns Created AK
   */
  async createAK(request?: CreateAKRequest): Promise<ApiResponse<CreateAKResponse>> {
    return this.client.post<CreateAKResponse>(this.buildUrl('/ak'), request ?? {});
  }

  /**
   * Get Attestation Key
   *
   * @param request - Optional filter parameters
   * @returns AK information
   */
  async getAK(request?: GetAKRequest): Promise<ApiResponse<GetAKResponse>> {
    return this.client.get<GetAKResponse>(this.buildUrl('/ak', {
      filters: { algorithm: request?.algorithm, handle: request?.handle?.toString() },
    }));
  }

  /**
   * Delete AK
   *
   * @param request - Delete request
   * @returns Delete result
   */
  async deleteAK(request: DeleteAKRequest): Promise<ApiResponse<DeleteAKResponse>> {
    return this.client.delete<DeleteAKResponse>(this.buildUrl(`/ak/${request.handle}`));
  }

  // =========================================================================
  // Seal/Unseal Operations
  // =========================================================================

  /**
   * Seal data to TPM
   *
   * @param request - Seal request
   * @returns Sealed data
   */
  async seal(request: SealRequest): Promise<ApiResponse<SealResponse>> {
    return this.client.post<SealResponse>(this.buildUrl('/seal'), request);
  }

  /**
   * Unseal data from TPM
   *
   * @param request - Unseal request
   * @returns Unsealed data
   */
  async unseal(request: UnsealRequest): Promise<ApiResponse<UnsealResponse>> {
    return this.client.post<UnsealResponse>(this.buildUrl('/unseal'), request);
  }

  // =========================================================================
  // Quote Operations
  // =========================================================================

  /**
   * Generate TPM quote
   *
   * @param request - Quote request
   * @returns Quote and signature
   */
  async quote(request: QuoteRequest): Promise<ApiResponse<QuoteResponse>> {
    return this.client.post<QuoteResponse>(this.buildUrl('/quote'), request);
  }

  /**
   * Verify TPM quote
   *
   * @param request - Verification request
   * @returns Verification result
   */
  async verifyQuote(request: VerifyQuoteRequest): Promise<ApiResponse<VerifyQuoteResponse>> {
    return this.client.post<VerifyQuoteResponse>(this.buildUrl('/quote/verify'), request);
  }

  // =========================================================================
  // Event Log and PCR Operations
  // =========================================================================

  /**
   * Get TPM event log
   *
   * @param request - Optional format specification
   * @returns Event log
   */
  async getEventLog(request?: GetEventLogRequest): Promise<ApiResponse<GetEventLogResponse>> {
    return this.client.get<GetEventLogResponse>(this.buildUrl('/eventlog', {
      filters: { format: request?.format },
    }));
  }

  /**
   * Get PCR values
   *
   * @param request - PCR indices and bank
   * @returns PCR values
   */
  async getPCRs(request: GetPCRsRequest): Promise<ApiResponse<GetPCRsResponse>> {
    // The server's GetPCRs handler decodes the JSON body via
    // protojson, which requires the proto-canonical enum form for
    // the `bank` field (e.g. "PCR_BANK_SHA256"). The SDK exposes a
    // friendlier short form via the `PCRBank` type ("SHA256") so
    // callers don't have to spell out the full enum name. Translate
    // here so the request reaches the server in a form it accepts.
    // Without this translation the server reads the bank as
    // UNSPECIFIED and returns *every* bank's PCRs concatenated,
    // which surfaced as SHA-1 values rendered under a "SHA-256"
    // label on the PCR Banks dashboard.
    // `Omit` rather than an intersection: `GetPCRsRequest & { bank?: string }`
    // leaves `bank` as `PCRBank & string`, which is still `PCRBank`, so the
    // prefixed value only assigned under an `as any`. Widening the field
    // properly types the wire shape for what it is — the proto-canonical
    // string — and removes the cast rather than hiding behind it.
    const wireRequest: Omit<GetPCRsRequest, 'bank'> & { bank?: string } = { ...request };
    if (wireRequest.bank !== undefined && !wireRequest.bank.startsWith('PCR_BANK_')) {
      wireRequest.bank = `PCR_BANK_${wireRequest.bank}`;
    }
    return this.client.post<GetPCRsResponse>(this.buildUrl('/pcrs'), wireRequest);
  }

  // =========================================================================
  // NVRAM Operations
  // =========================================================================

  /**
   * Define NVRAM index
   *
   * @param request - NVRAM definition request
   * @returns Definition result
   */
  async defineNVRAM(request: DefineNVRAMRequest): Promise<ApiResponse<DefineNVRAMResponse>> {
    return this.client.post<DefineNVRAMResponse>(this.buildUrl('/nvram'), request);
  }

  /**
   * Write to NVRAM
   *
   * @param request - Write request
   * @returns Write result
   */
  async writeNVRAM(request: WriteNVRAMRequest): Promise<ApiResponse<WriteNVRAMResponse>> {
    return this.client.put<WriteNVRAMResponse>(this.buildUrl(`/nvram/${request.index}`), {
      data: request.data,
      password: request.password,
      offset: request.offset,
    });
  }

  /**
   * Read from NVRAM
   *
   * @param request - Read request
   * @returns Read data
   */
  async readNVRAM(request: ReadNVRAMRequest): Promise<ApiResponse<ReadNVRAMResponse>> {
    return this.client.get<ReadNVRAMResponse>(this.buildUrl(`/nvram/${request.index}`, {
      filters: {
        offset: request.offset?.toString(),
        size: request.size?.toString(),
      },
    }));
  }

  /**
   * Undefine NVRAM index
   *
   * @param request - Undefine request
   * @returns Undefine result
   */
  async undefineNVRAM(request: UndefineNVRAMRequest): Promise<ApiResponse<UndefineNVRAMResponse>> {
    return this.client.delete<UndefineNVRAMResponse>(this.buildUrl(`/nvram/${request.index}`));
  }

  // =========================================================================
  // Random Number Generation
  // =========================================================================

  /**
   * Get random bytes from TPM
   *
   * @param request - Number of bytes
   * @returns Random bytes
   */
  async getRandom(request: GetRandomRequest): Promise<ApiResponse<GetRandomResponse>> {
    return this.client.post<GetRandomResponse>(this.buildUrl('/random'), request);
  }
}
