/**
 * QuicBaaS Key Management Service
 *
 * Provides key management operations including key generation, import,
 * rotation, deletion, and encryption/decryption operations for QuicBaaS.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  QuicBaaSGenerateKeyRequest,
  QuicBaaSGenerateKeyResponse,
  QuicBaaSImportKeyRequest,
  QuicBaaSImportKeyResponse,
  QuicBaaSGetKeyRequest,
  QuicBaaSGetKeyResponse,
  QuicBaaSListKeysRequest,
  QuicBaaSListKeysResponse,
  QuicBaaSRotateKeyRequest,
  QuicBaaSRotateKeyResponse,
  QuicBaaSDeleteKeyRequest,
  QuicBaaSDeleteKeyResponse,
  QuicBaaSKMSEncryptRequest,
  QuicBaaSKMSEncryptResponse,
  QuicBaaSKMSDecryptRequest,
  QuicBaaSKMSDecryptResponse,
} from '../../types/quicbaas/security-part1.js';

/**
 * QuicBaaS Key Management Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Generate a new encryption key
 * const keyResult = await client.quicbaas.kms.generateKey({
 *   name: 'my-encryption-key',
 *   algorithm: 'AES_256',
 *   exportable: false,
 *   autoRotate: true,
 *   rotationIntervalDays: 90,
 * });
 *
 * if (keyResult.success && keyResult.data?.key) {
 *   const keyId = keyResult.data.key.keyId;
 *
 *   // Encrypt data with the key
 *   const encryptResult = await client.quicbaas.kms.encrypt({
 *     keyId,
 *     plaintext: btoa('sensitive data'),
 *   });
 *
 *   // Decrypt data
 *   const decryptResult = await client.quicbaas.kms.decrypt({
 *     keyId,
 *     ciphertext: encryptResult.data.ciphertext,
 *   });
 *
 *   // Rotate the key
 *   await client.quicbaas.kms.rotateKey({ keyId });
 * }
 *
 * // List all keys
 * const keysResult = await client.quicbaas.kms.listKeys({
 *   status: 'active',
 *   pageSize: 50,
 * });
 * ```
 */
export class QuicBaaSKMSService extends BaseService {
  /**
   * Creates a new QuicBaaS KMS service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas/kms');
  }

  // =========================================================================
  // Key Management Operations
  // =========================================================================

  /**
   * Generate a new cryptographic key
   *
   * Creates a new key with the specified algorithm and configuration.
   * Supports symmetric keys (AES), asymmetric keys (RSA, ECDSA), and
   * signing keys (ED25519).
   *
   * @param request - Key generation request with algorithm and options
   * @returns Generated key metadata
   */
  async generateKey(request: QuicBaaSGenerateKeyRequest): Promise<ApiResponse<QuicBaaSGenerateKeyResponse>> {
    return this.client.post<QuicBaaSGenerateKeyResponse>(this.buildUrl('/keys'), request);
  }

  /**
   * Import an existing key
   *
   * Imports external key material into QuicBaaS KMS. The key material
   * must be base64 encoded and match the specified algorithm.
   *
   * @param request - Key import request with key material
   * @returns Imported key metadata
   */
  async importKey(request: QuicBaaSImportKeyRequest): Promise<ApiResponse<QuicBaaSImportKeyResponse>> {
    return this.client.post<QuicBaaSImportKeyResponse>(this.buildUrl('/keys/import'), request);
  }

  /**
   * Get key metadata by ID
   *
   * Retrieves metadata for a specific key. Optionally retrieves
   * a specific version of the key.
   *
   * @param keyId - Key identifier
   * @param version - Optional specific version number
   * @returns Key metadata
   */
  async getKey(keyId: string, version?: number): Promise<ApiResponse<QuicBaaSGetKeyResponse>> {
    const url = version !== undefined
      ? this.buildUrl(`/keys/${this.encodePathSegment(keyId)}?version=${version}`)
      : this.buildUrl(`/keys/${this.encodePathSegment(keyId)}`);
    return this.client.get<QuicBaaSGetKeyResponse>(url);
  }

  /**
   * List keys with optional filtering
   *
   * Returns a paginated list of keys with optional filtering by
   * status, algorithm, name prefix, or tags.
   *
   * @param options - List options with filtering and pagination
   * @returns List of key metadata
   */
  async listKeys(options?: QuicBaaSListKeysRequest): Promise<ApiResponse<QuicBaaSListKeysResponse>> {
    return this.client.get<QuicBaaSListKeysResponse>(this.buildUrl('/keys', {
      page: options?.page,
      limit: options?.pageSize,
      filters: {
        status: options?.status,
        algorithm: options?.algorithm,
        namePrefix: options?.namePrefix,
        ...options?.tags,
      },
    }));
  }

  /**
   * Rotate a key to create a new version
   *
   * Creates a new version of the key. Previous versions remain available
   * for decryption but new encryption operations use the latest version.
   *
   * @param request - Key rotation request
   * @returns Rotation result with old and new version numbers
   */
  async rotateKey(request: QuicBaaSRotateKeyRequest): Promise<ApiResponse<QuicBaaSRotateKeyResponse>> {
    return this.client.post<QuicBaaSRotateKeyResponse>(
      this.buildUrl(`/keys/${this.encodePathSegment(request.keyId)}/rotate`),
      {}
    );
  }

  /**
   * Delete a key
   *
   * Schedules a key for deletion or immediately deletes it if force
   * is specified. Keys in pending deletion can be recovered within
   * the pending window.
   *
   * @param request - Key deletion request
   * @returns Deletion result with new status
   */
  async deleteKey(request: QuicBaaSDeleteKeyRequest): Promise<ApiResponse<QuicBaaSDeleteKeyResponse>> {
    const url = this.buildUrl(`/keys/${this.encodePathSegment(request.keyId)}`, {
      filters: {
        force: request.force?.toString(),
        pendingWindowDays: request.pendingWindowDays?.toString(),
      },
    });
    return this.client.delete<QuicBaaSDeleteKeyResponse>(url);
  }

  // =========================================================================
  // Cryptographic Operations
  // =========================================================================

  /**
   * Encrypt data using a key
   *
   * Encrypts plaintext data using the specified key. The plaintext
   * must be base64 encoded. Additional authenticated data (context)
   * can be provided for AEAD ciphers.
   *
   * @param request - Encryption request with key ID and plaintext
   * @returns Encrypted ciphertext
   */
  async encrypt(request: QuicBaaSKMSEncryptRequest): Promise<ApiResponse<QuicBaaSKMSEncryptResponse>> {
    return this.client.post<QuicBaaSKMSEncryptResponse>(this.buildUrl('/encrypt'), request);
  }

  /**
   * Decrypt data using a key
   *
   * Decrypts ciphertext data using the specified key. The ciphertext
   * must be base64 encoded. The same context used during encryption
   * must be provided for AEAD ciphers.
   *
   * @param request - Decryption request with key ID and ciphertext
   * @returns Decrypted plaintext
   */
  async decrypt(request: QuicBaaSKMSDecryptRequest): Promise<ApiResponse<QuicBaaSKMSDecryptResponse>> {
    return this.client.post<QuicBaaSKMSDecryptResponse>(this.buildUrl('/decrypt'), request);
  }
}
