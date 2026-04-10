/**
 * Key Management Service
 *
 * Provides operations for key management and cryptographic operations
 * including key generation, encryption, signing, and HMAC.
 */

import type { ApiClient } from '../client/api-client.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  GenerateKeyRequest,
  ImportKeyRequest,
  ListKeysRequest,
  DeleteKeyRequest,
  RotateKeyRequest,
  UpdateKeyStatusRequest,
  ExportKeyRequest,
  EncryptRequest,
  DecryptRequest,
  SignRequest,
  VerifyRequest,
  HashRequest,
  HMACRequest,
  VerifyHMACRequest,
  GenerateRandomRequest,
  GenerateDataKeyRequest,
  GenerateWrappedDataKeyRequest,
  GetKeyVersionsRequest,
  GenerateKeyResponse,
  ImportKeyResponse,
  GetKeyResponse,
  ListKeysResponse,
  DeleteKeyResponse,
  RotateKeyResponse,
  UpdateKeyStatusResponse,
  ExportKeyResponse,
  GetKeyVersionsResponse,
  EncryptResponse,
  DecryptResponse,
  SignResponse,
  VerifyResponse,
  HashResponse,
  HMACResponse,
  VerifyHMACResponse,
  GenerateRandomResponse,
  GenerateDataKeyResponse,
  GenerateWrappedDataKeyResponse,
  BackendStatusResponse,
} from '../types/kms.js';

/**
 * Key Management Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Generate a key
 * const key = await client.kms.generateKey({
 *   keySpec: { algorithm: 'AES_256', usage: ['ENCRYPT', 'DECRYPT'] },
 *   name: 'my-encryption-key',
 * });
 *
 * // Encrypt data
 * const encrypted = await client.kms.encrypt({
 *   keyId: key.data.key.keyId,
 *   plaintext: btoa('Hello, World!'),
 * });
 *
 * // Decrypt data
 * const decrypted = await client.kms.decrypt({
 *   keyId: key.data.key.keyId,
 *   ciphertext: encrypted.data.ciphertext,
 * });
 * ```
 */
export class KMSService extends BaseService {
  /**
   * Creates a new KMS service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/kms');
  }

  // =========================================================================
  // Key Management
  // =========================================================================

  /**
   * Generate a new key
   *
   * @param request - Key generation request
   * @returns Generated key handle and metadata
   */
  async generateKey(request: GenerateKeyRequest): Promise<ApiResponse<GenerateKeyResponse>> {
    return this.client.post<GenerateKeyResponse>(this.buildUrl('/keys'), request);
  }

  /**
   * Import an existing key
   *
   * @param request - Key import request with key material
   * @returns Imported key handle and metadata
   */
  async importKey(request: ImportKeyRequest): Promise<ApiResponse<ImportKeyResponse>> {
    return this.client.post<ImportKeyResponse>(this.buildUrl('/keys/import'), request);
  }

  /**
   * Get key by ID
   *
   * @param keyId - Key identifier
   * @param version - Optional specific version
   * @returns Key handle and metadata
   */
  async getKey(keyId: string, version?: number): Promise<ApiResponse<GetKeyResponse>> {
    const url = version !== undefined
      ? this.buildUrl(`/keys/${this.encodePathSegment(keyId)}?version=${version}`)
      : this.buildUrl(`/keys/${this.encodePathSegment(keyId)}`);
    return this.client.get<GetKeyResponse>(url);
  }

  /**
   * List all keys
   *
   * @param options - List options with filtering
   * @returns List of key handles
   */
  async listKeys(options?: ListKeysRequest): Promise<ApiResponse<ListKeysResponse>> {
    return this.client.get<ListKeysResponse>(this.buildUrl('/keys', {
      limit: options?.limit,
      filters: options?.filter,
    }));
  }

  /**
   * Delete a key
   *
   * @param request - Delete request with key ID
   * @returns Deletion result
   */
  async deleteKey(request: DeleteKeyRequest): Promise<ApiResponse<DeleteKeyResponse>> {
    const url = this.buildUrl(`/keys/${this.encodePathSegment(request.keyId)}`, {
      filters: {
        pendingWindowDays: request.pendingWindowDays?.toString(),
        force: request.force?.toString(),
      },
    });
    return this.client.delete<DeleteKeyResponse>(url);
  }

  /**
   * Rotate a key (create new version)
   *
   * @param request - Rotation request
   * @returns New key version
   */
  async rotateKey(request: RotateKeyRequest): Promise<ApiResponse<RotateKeyResponse>> {
    return this.client.post<RotateKeyResponse>(
      this.buildUrl(`/keys/${this.encodePathSegment(request.keyId)}/rotate`),
      { retainOldVersion: request.retainOldVersion }
    );
  }

  /**
   * Update key status (enable/disable)
   *
   * @param request - Status update request
   * @returns Updated key status
   */
  async updateKeyStatus(request: UpdateKeyStatusRequest): Promise<ApiResponse<UpdateKeyStatusResponse>> {
    return this.client.patch<UpdateKeyStatusResponse>(
      this.buildUrl(`/keys/${this.encodePathSegment(request.keyId)}/status`),
      { version: request.version, status: request.status }
    );
  }

  /**
   * Export a key (if exportable)
   *
   * @param request - Export request with wrapping options
   * @returns Wrapped key material
   */
  async exportKey(request: ExportKeyRequest): Promise<ApiResponse<ExportKeyResponse>> {
    return this.client.post<ExportKeyResponse>(
      this.buildUrl(`/keys/${this.encodePathSegment(request.keyId)}/export`),
      {
        wrappingKeyId: request.wrappingKeyId,
        wrappingAlgorithm: request.wrappingAlgorithm,
        format: request.format,
        version: request.version,
      }
    );
  }

  /**
   * Get key versions
   *
   * @param request - Request with key ID and pagination
   * @returns List of key versions
   */
  async getKeyVersions(request: GetKeyVersionsRequest): Promise<ApiResponse<GetKeyVersionsResponse>> {
    return this.client.get<GetKeyVersionsResponse>(
      this.buildUrl(`/keys/${this.encodePathSegment(request.keyId)}/versions`, {
        limit: request.limit,
      })
    );
  }

  // =========================================================================
  // Cryptographic Operations
  // =========================================================================

  /**
   * Encrypt plaintext
   *
   * @param request - Encryption request
   * @returns Ciphertext
   */
  async encrypt(request: EncryptRequest): Promise<ApiResponse<EncryptResponse>> {
    return this.client.post<EncryptResponse>(this.buildUrl('/encrypt'), request);
  }

  /**
   * Decrypt ciphertext
   *
   * @param request - Decryption request
   * @returns Plaintext
   */
  async decrypt(request: DecryptRequest): Promise<ApiResponse<DecryptResponse>> {
    return this.client.post<DecryptResponse>(this.buildUrl('/decrypt'), request);
  }

  /**
   * Sign a message
   *
   * @param request - Signing request
   * @returns Signature
   */
  async sign(request: SignRequest): Promise<ApiResponse<SignResponse>> {
    return this.client.post<SignResponse>(this.buildUrl('/sign'), request);
  }

  /**
   * Verify a signature
   *
   * @param request - Verification request
   * @returns Verification result
   */
  async verify(request: VerifyRequest): Promise<ApiResponse<VerifyResponse>> {
    return this.client.post<VerifyResponse>(this.buildUrl('/verify'), request);
  }

  /**
   * Compute hash
   *
   * @param request - Hash request
   * @returns Hash value
   */
  async hash(request: HashRequest): Promise<ApiResponse<HashResponse>> {
    return this.client.post<HashResponse>(this.buildUrl('/hash'), request);
  }

  /**
   * Compute HMAC
   *
   * @param request - HMAC request
   * @returns HMAC value
   */
  async hmac(request: HMACRequest): Promise<ApiResponse<HMACResponse>> {
    return this.client.post<HMACResponse>(this.buildUrl('/hmac'), request);
  }

  /**
   * Verify HMAC
   *
   * @param request - HMAC verification request
   * @returns Verification result
   */
  async verifyHMAC(request: VerifyHMACRequest): Promise<ApiResponse<VerifyHMACResponse>> {
    return this.client.post<VerifyHMACResponse>(this.buildUrl('/hmac/verify'), request);
  }

  // =========================================================================
  // Key Generation Helpers
  // =========================================================================

  /**
   * Generate random bytes
   *
   * @param request - Random generation request
   * @returns Random bytes
   */
  async generateRandom(request: GenerateRandomRequest): Promise<ApiResponse<GenerateRandomResponse>> {
    return this.client.post<GenerateRandomResponse>(this.buildUrl('/random'), request);
  }

  /**
   * Generate a data key (plaintext + encrypted)
   *
   * @param request - Data key generation request
   * @returns Plaintext and encrypted data key
   */
  async generateDataKey(request: GenerateDataKeyRequest): Promise<ApiResponse<GenerateDataKeyResponse>> {
    return this.client.post<GenerateDataKeyResponse>(this.buildUrl('/datakey'), request);
  }

  /**
   * Generate a wrapped data key (encrypted only)
   *
   * @param request - Wrapped data key generation request
   * @returns Wrapped data key
   */
  async generateWrappedDataKey(request: GenerateWrappedDataKeyRequest): Promise<ApiResponse<GenerateWrappedDataKeyResponse>> {
    return this.client.post<GenerateWrappedDataKeyResponse>(this.buildUrl('/datakey/wrapped'), request);
  }

  // =========================================================================
  // Backend Operations
  // =========================================================================

  /**
   * Get backend status
   *
   * @returns Backend status and capabilities
   */
  async getBackendStatus(): Promise<ApiResponse<BackendStatusResponse>> {
    return this.client.get<BackendStatusResponse>(this.buildUrl('/backend/status'));
  }
}
