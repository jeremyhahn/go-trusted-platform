/**
 * Key Management Service
 *
 * Provides operations for key management and cryptographic operations
 * including key generation, encryption, signing, and HMAC.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
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
 * Builds a REST wire body, leaving out fields that are undefined so the
 * server's `omitempty` defaults apply.
 */
function wireBody(fields: Record<string, unknown>): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined) {
      body[key] = value;
    }
  }
  return body;
}

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
  constructor(client: Transport | ApiClient) {
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
   * Import an existing key: `POST /keys/import` with the server's
   * snake_case ImportKeyRequest body.
   *
   * @param request - Key import request with key material
   * @returns Imported key handle and metadata
   */
  async importKey(request: ImportKeyRequest): Promise<ApiResponse<ImportKeyResponse>> {
    return this.client.post<ImportKeyResponse>(this.buildUrl('/keys/import'), wireBody({
      name: request.name,
      algorithm: request.keySpec.algorithm,
      key_material: request.keyMaterial,
      wrapping_key_id: request.wrappingKeyId,
      usage: request.keySpec.usage,
      description: request.description,
      tags: request.tags,
    }));
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
   * Update key status (enable/disable): `PUT /keys/{name}/status`.
   *
   * @param request - Status update request
   * @returns Updated key status
   */
  async updateKeyStatus(request: UpdateKeyStatusRequest): Promise<ApiResponse<UpdateKeyStatusResponse>> {
    return this.client.put<UpdateKeyStatusResponse>(
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
   * Encrypt plaintext: POST /v1/kms/encrypt/{name} with { plaintext, context }
   *
   * @param request - Encryption request
   * @returns Ciphertext
   */
  async encrypt(request: EncryptRequest): Promise<ApiResponse<EncryptResponse>> {
    return this.client.post<EncryptResponse>(
      this.buildUrl(`/encrypt/${this.encodePathSegment(request.keyId)}`),
      wireBody({ plaintext: request.plaintext, context: request.context })
    );
  }

  /**
   * Decrypt ciphertext: POST /v1/kms/decrypt/{name} with { ciphertext, context, version }
   *
   * @param request - Decryption request
   * @returns Plaintext
   */
  async decrypt(request: DecryptRequest): Promise<ApiResponse<DecryptResponse>> {
    return this.client.post<DecryptResponse>(
      this.buildUrl(`/decrypt/${this.encodePathSegment(request.keyId)}`),
      wireBody({ ciphertext: request.ciphertext, context: request.context, version: request.keyVersion })
    );
  }

  /**
   * Sign a message: POST /v1/kms/sign/{name} with { data, hash, version, pre_hashed }
   *
   * @param request - Signing request
   * @returns Signature
   */
  async sign(request: SignRequest): Promise<ApiResponse<SignResponse>> {
    // The REST Sign handler never reads a version and always signs with the
    // current key, so a selected older version would be silently ignored:
    // refuse it before sending.
    if (request.keyVersion) {
      throw new RangeError(
        'sign key version selection is not supported: the daemon always signs with the current key'
      );
    }
    return this.client.post<SignResponse>(
      this.buildUrl(`/sign/${this.encodePathSegment(request.keyId)}`),
      wireBody({
        data: request.message,
        hash: request.hashAlgorithm,
        pre_hashed: request.preHashed,
      })
    );
  }

  /**
   * Verify a signature: POST /v1/kms/verify/{name} with { data, signature, hash, version }
   *
   * @param request - Verification request
   * @returns Verification result
   */
  async verify(request: VerifyRequest): Promise<ApiResponse<VerifyResponse>> {
    return this.client.post<VerifyResponse>(
      this.buildUrl(`/verify/${this.encodePathSegment(request.keyId)}`),
      wireBody({
        data: request.message,
        signature: request.signature,
        hash: request.hashAlgorithm,
        version: request.keyVersion,
      })
    );
  }

  /**
   * Compute hash: `POST /hash` with `{ data, hash }`.
   *
   * @param request - Hash request
   * @returns Hash value
   */
  async hash(request: HashRequest): Promise<ApiResponse<HashResponse>> {
    return this.client.post<HashResponse>(this.buildUrl('/hash'), { data: request.data, hash: request.algorithm });
  }

  /**
   * Compute HMAC: `POST /hmac/{name}` with `{ data, hash }`.
   *
   * @param request - HMAC request
   * @returns HMAC value
   */
  async hmac(request: HMACRequest): Promise<ApiResponse<HMACResponse>> {
    return this.client.post<HMACResponse>(
      this.buildUrl(`/hmac/${this.encodePathSegment(request.keyId)}`),
      wireBody({ data: request.message, hash: request.hashAlgorithm })
    );
  }

  /**
   * Verify HMAC: `POST /hmac/{name}/verify` with `{ data, hmac, hash }`.
   *
   * @param request - HMAC verification request
   * @returns Verification result
   */
  async verifyHMAC(request: VerifyHMACRequest): Promise<ApiResponse<VerifyHMACResponse>> {
    return this.client.post<VerifyHMACResponse>(
      this.buildUrl(`/hmac/${this.encodePathSegment(request.keyId)}/verify`),
      wireBody({ data: request.message, hmac: request.hmac, hash: request.hashAlgorithm })
    );
  }

  // =========================================================================
  // Key Generation Helpers
  // =========================================================================

  /**
   * Generate random bytes: `POST /random` with `{ num_bytes }`.
   *
   * @param request - Random generation request
   * @returns Random bytes
   */
  async generateRandom(request: GenerateRandomRequest): Promise<ApiResponse<GenerateRandomResponse>> {
    return this.client.post<GenerateRandomResponse>(this.buildUrl('/random'), { num_bytes: request.numBytes });
  }

  /**
   * Generate a data key (plaintext + encrypted): `POST /data-keys` with
   * `{ key_id, algorithm, key_size, context }`.
   *
   * @param request - Data key generation request
   * @returns Plaintext and encrypted data key
   */
  async generateDataKey(request: GenerateDataKeyRequest): Promise<ApiResponse<GenerateDataKeyResponse>> {
    return this.client.post<GenerateDataKeyResponse>(this.buildUrl('/data-keys'), wireBody({
      key_id: request.keyId,
      algorithm: request.algorithm,
      key_size: request.keySize,
      context: request.context,
    }));
  }

  /**
   * Generate a wrapped data key (encrypted only): `POST /data-keys/wrapped`
   * with `{ wrapping_key_id, key_algorithm, key_size, context }`.
   *
   * @param request - Wrapped data key generation request
   * @returns Wrapped data key
   */
  async generateWrappedDataKey(request: GenerateWrappedDataKeyRequest): Promise<ApiResponse<GenerateWrappedDataKeyResponse>> {
    return this.client.post<GenerateWrappedDataKeyResponse>(this.buildUrl('/data-keys/wrapped'), wireBody({
      wrapping_key_id: request.wrappingKeyId,
      key_algorithm: request.keyAlgorithm,
      key_size: request.keySize,
      context: request.context,
    }));
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
