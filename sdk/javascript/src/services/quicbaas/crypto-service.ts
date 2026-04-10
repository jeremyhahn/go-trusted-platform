/**
 * QuicBaaS Crypto Service
 *
 * Provides cryptographic operations including encryption, decryption,
 * signing, verification, hashing, and random data generation.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  CryptoEncryptRequest,
  CryptoEncryptResponse,
  CryptoDecryptRequest,
  CryptoDecryptResponse,
  CryptoSignRequest,
  CryptoSignResponse,
  CryptoVerifyRequest,
  CryptoVerifyResponse,
  CryptoHashRequest,
  CryptoHashResponse,
  CryptoGenerateRandomRequest,
  CryptoGenerateRandomResponse,
} from '../../types/quicbaas/security-part1.js';

/**
 * QuicBaaS Crypto Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Encrypt data
 * const encryptResult = await client.quicbaas.crypto.encrypt({
 *   plaintext: btoa('sensitive data'),
 *   algorithm: 'AES_GCM',
 *   keyId: 'my-encryption-key',
 * });
 *
 * // Decrypt data
 * const decryptResult = await client.quicbaas.crypto.decrypt({
 *   ciphertext: encryptResult.data.ciphertext,
 *   nonce: encryptResult.data.nonce,
 *   algorithm: 'AES_GCM',
 *   keyId: 'my-encryption-key',
 * });
 *
 * // Sign data
 * const signResult = await client.quicbaas.crypto.sign({
 *   keyId: 'my-signing-key',
 *   data: btoa('data to sign'),
 *   algorithm: 'ECDSA_SHA256',
 * });
 *
 * // Verify signature
 * const verifyResult = await client.quicbaas.crypto.verify({
 *   keyId: 'my-signing-key',
 *   data: btoa('data to sign'),
 *   signature: signResult.data.signature,
 *   algorithm: 'ECDSA_SHA256',
 * });
 *
 * // Hash data
 * const hashResult = await client.quicbaas.crypto.hash({
 *   data: btoa('data to hash'),
 *   algorithm: 'SHA256',
 * });
 *
 * // Generate random bytes
 * const randomResult = await client.quicbaas.crypto.generateRandom({
 *   length: 32,
 *   format: 'base64',
 * });
 * ```
 */
export class QuicBaaSCryptoService extends BaseService {
  /**
   * Creates a new QuicBaaS Crypto service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas/crypto');
  }

  // =========================================================================
  // Encryption/Decryption Operations
  // =========================================================================

  /**
   * Encrypt plaintext data
   *
   * Encrypts data using the specified algorithm and key. The plaintext
   * must be base64 encoded. Supports various algorithms including
   * AES-GCM, AES-CBC, ChaCha20-Poly1305, and RSA-OAEP.
   *
   * @param request - Encryption request with plaintext and options
   * @returns Encrypted ciphertext with nonce and tag
   */
  async encrypt(request: CryptoEncryptRequest): Promise<ApiResponse<CryptoEncryptResponse>> {
    return this.client.post<CryptoEncryptResponse>(this.buildUrl('/encrypt'), request);
  }

  /**
   * Decrypt ciphertext data
   *
   * Decrypts data using the specified algorithm and key. The ciphertext
   * must be base64 encoded. For AEAD ciphers, the nonce and tag must
   * be provided.
   *
   * @param request - Decryption request with ciphertext and options
   * @returns Decrypted plaintext
   */
  async decrypt(request: CryptoDecryptRequest): Promise<ApiResponse<CryptoDecryptResponse>> {
    return this.client.post<CryptoDecryptResponse>(this.buildUrl('/decrypt'), request);
  }

  // =========================================================================
  // Signing/Verification Operations
  // =========================================================================

  /**
   * Sign data with a key
   *
   * Creates a digital signature over the provided data using the
   * specified key and algorithm. The data must be base64 encoded.
   * Supports RSA, ECDSA, and ED25519 signatures.
   *
   * @param request - Signing request with data and key
   * @returns Signature
   */
  async sign(request: CryptoSignRequest): Promise<ApiResponse<CryptoSignResponse>> {
    return this.client.post<CryptoSignResponse>(this.buildUrl('/sign'), request);
  }

  /**
   * Verify a signature
   *
   * Verifies a digital signature over the provided data using the
   * specified key and algorithm. Returns whether the signature is
   * valid.
   *
   * @param request - Verification request with data, signature, and key
   * @returns Verification result
   */
  async verify(request: CryptoVerifyRequest): Promise<ApiResponse<CryptoVerifyResponse>> {
    return this.client.post<CryptoVerifyResponse>(this.buildUrl('/verify'), request);
  }

  // =========================================================================
  // Hashing Operations
  // =========================================================================

  /**
   * Compute a hash of data
   *
   * Computes a cryptographic hash of the provided data using the
   * specified algorithm. The data must be base64 encoded. Supports
   * SHA-2, SHA-3, BLAKE2b, and BLAKE3 algorithms.
   *
   * @param request - Hash request with data and algorithm
   * @returns Hash value
   */
  async hash(request: CryptoHashRequest): Promise<ApiResponse<CryptoHashResponse>> {
    return this.client.post<CryptoHashResponse>(this.buildUrl('/hash'), request);
  }

  // =========================================================================
  // Random Generation
  // =========================================================================

  /**
   * Generate cryptographically secure random bytes
   *
   * Generates random bytes from a cryptographically secure random
   * number generator. Returns the data in the specified format
   * (base64 or hex).
   *
   * @param request - Random generation request with length and format
   * @returns Random data
   */
  async generateRandom(request: CryptoGenerateRandomRequest): Promise<ApiResponse<CryptoGenerateRandomResponse>> {
    return this.client.post<CryptoGenerateRandomResponse>(this.buildUrl('/random'), request);
  }
}
