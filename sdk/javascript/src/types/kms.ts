/**
 * Key Management Service (KMS) Types
 *
 * Types for KMS operations including key management and cryptographic operations.
 * Based on pkg/api/grpc/proto/kms.proto
 */

// =============================================================================
// Enums
// =============================================================================

/**
 * KMS key algorithm including symmetric algorithms
 */
export type KMSKeyAlgorithm =
  | 'UNSPECIFIED'
  // Asymmetric algorithms
  | 'RSA_2048'
  | 'RSA_3072'
  | 'RSA_4096'
  | 'ECDSA_P256'
  | 'ECDSA_P384'
  | 'ECDSA_P521'
  | 'ED25519'
  // Post-quantum algorithms
  | 'DILITHIUM2'
  | 'DILITHIUM3'
  | 'DILITHIUM5'
  // Symmetric algorithms
  | 'AES_128'
  | 'AES_192'
  | 'AES_256'
  | 'CHACHA20_POLY1305'
  // HMAC algorithms
  | 'HMAC_SHA256'
  | 'HMAC_SHA384'
  | 'HMAC_SHA512';

/**
 * Key usage defines what operations a key can perform
 */
export type KeyUsage =
  | 'UNSPECIFIED'
  | 'ENCRYPT'
  | 'DECRYPT'
  | 'SIGN'
  | 'VERIFY'
  | 'WRAP'
  | 'UNWRAP'
  | 'DERIVE'
  | 'HMAC';

/**
 * Key status indicates the current state of a key
 */
export type KeyStatus =
  | 'UNSPECIFIED'
  | 'ENABLED'
  | 'DISABLED'
  | 'PENDING_DELETION'
  | 'DESTROYED'
  | 'PENDING_IMPORT';

/**
 * Key export format
 */
export type KeyExportFormat =
  | 'UNSPECIFIED'
  | 'RAW'
  | 'PKCS8'
  | 'JWK'
  | 'PEM';

/**
 * Wrapping algorithm for key export/import
 */
export type WrappingAlgorithm =
  | 'UNSPECIFIED'
  | 'RSA_OAEP_SHA256'
  | 'RSA_OAEP_SHA384'
  | 'RSA_OAEP_SHA512'
  | 'AES_GCM'
  | 'AES_KWP';

/**
 * Hash algorithm
 */
export type HashAlgorithm =
  | 'UNSPECIFIED'
  | 'SHA1'
  | 'SHA256'
  | 'SHA384'
  | 'SHA512'
  | 'SHA3_256'
  | 'SHA3_384'
  | 'SHA3_512';

// =============================================================================
// Data Types
// =============================================================================

/**
 * Key specification for key generation
 */
export interface KMSKeySpec {
  /** Key algorithm */
  algorithm: KMSKeyAlgorithm;
  /** Key size in bits (optional, algorithm-dependent) */
  keySize?: number;
  /** Allowed key usages */
  usage: KeyUsage[];
  /** Whether the key can be exported */
  exportable?: boolean;
  /** Whether deletion protection is enabled */
  deletionProtection?: boolean;
}

/**
 * Key handle represents a reference to a key
 */
export interface KMSKeyHandle {
  /** Key ID */
  keyId: string;
  /** Key version */
  version: number;
  /** Key algorithm */
  algorithm: KMSKeyAlgorithm;
  /** Key status */
  status: KeyStatus;
  /** Creation timestamp (unix epoch) */
  createdAt: number;
}

/**
 * Key metadata contains detailed information about a key
 */
export interface KMSKeyMetadata {
  /** Key ID */
  keyId: string;
  /** Key name */
  name: string;
  /** Key description */
  description?: string;
  /** Key algorithm */
  algorithm: KMSKeyAlgorithm;
  /** Key status */
  status: KeyStatus;
  /** Allowed key usages */
  usage: KeyUsage[];
  /** Key version */
  version: number;
  /** Whether the key can be exported */
  exportable: boolean;
  /** Whether deletion protection is enabled */
  deletionProtection: boolean;
  /** Creation timestamp (unix epoch) */
  createdAt: number;
  /** Last update timestamp (unix epoch) */
  updatedAt: number;
  /** Last used timestamp (unix epoch) */
  lastUsedAt?: number;
  /** Key tags */
  tags?: Record<string, string>;
  /** Key owner */
  owner?: string;
}

/**
 * Key version information
 */
export interface KMSKeyVersionInfo {
  /** Version number */
  version: number;
  /** Version status */
  status: KeyStatus;
  /** Algorithm */
  algorithm: KMSKeyAlgorithm;
  /** Creation timestamp (unix epoch) */
  createdAt: number;
  /** Disabled timestamp (unix epoch) */
  disabledAt?: number;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Generate key request
 */
export interface GenerateKeyRequest {
  /** Key specification */
  keySpec: KMSKeySpec;
  /** Key name */
  name: string;
  /** Key description */
  description?: string;
  /** Key tags */
  tags?: Record<string, string>;
  /** Key owner */
  owner?: string;
}

/**
 * Import key request
 */
export interface ImportKeyRequest {
  /** Key material (base64) */
  keyMaterial: string;
  /** Wrapping key ID (if key is wrapped) */
  wrappingKeyId?: string;
  /** Key specification */
  keySpec: KMSKeySpec;
  /** Key name */
  name: string;
  /** Key description */
  description?: string;
  /** Key tags */
  tags?: Record<string, string>;
}

/**
 * Get key request
 */
export interface GetKeyRequest {
  /** Key ID */
  keyId: string;
  /** Specific version (optional) */
  version?: number;
}

/**
 * List keys request
 */
export interface ListKeysRequest {
  /** Maximum number of results */
  limit?: number;
  /** Cursor for pagination */
  cursor?: string;
  /** Filter by key-value pairs */
  filter?: Record<string, string>;
}

/**
 * Delete key request
 */
export interface DeleteKeyRequest {
  /** Key ID */
  keyId: string;
  /** Pending deletion window in days */
  pendingWindowDays?: number;
  /** Force immediate deletion */
  force?: boolean;
}

/**
 * Rotate key request
 */
export interface RotateKeyRequest {
  /** Key ID */
  keyId: string;
  /** Whether to retain the old version */
  retainOldVersion?: boolean;
}

/**
 * Update key status request
 */
export interface UpdateKeyStatusRequest {
  /** Key ID */
  keyId: string;
  /** Key version */
  version?: number;
  /** New status */
  status: KeyStatus;
}

/**
 * Export key request
 */
export interface ExportKeyRequest {
  /** Key ID */
  keyId: string;
  /** Wrapping key ID */
  wrappingKeyId?: string;
  /** Wrapping algorithm */
  wrappingAlgorithm?: WrappingAlgorithm;
  /** Export format */
  format?: KeyExportFormat;
  /** Key version */
  version?: number;
}

/**
 * Get key versions request
 */
export interface GetKeyVersionsRequest {
  /** Key ID */
  keyId: string;
  /** Maximum number of results */
  limit?: number;
  /** Cursor for pagination */
  cursor?: string;
}

/**
 * Encrypt request
 */
export interface EncryptRequest {
  /** Key ID */
  keyId: string;
  /** Plaintext data (base64) */
  plaintext: string;
  /** Additional authenticated data (base64) */
  context?: string;
  /** Nonce (base64) */
  nonce?: string;
}

/**
 * Decrypt request
 */
export interface DecryptRequest {
  /** Key ID */
  keyId: string;
  /** Ciphertext data (base64) */
  ciphertext: string;
  /** Additional authenticated data (base64) */
  context?: string;
  /** Nonce (base64) */
  nonce?: string;
  /** Key version used for encryption */
  keyVersion?: number;
}

/**
 * Sign request
 */
export interface SignRequest {
  /** Key ID */
  keyId: string;
  /** Message to sign (base64) */
  message: string;
  /** Hash algorithm */
  hashAlgorithm?: HashAlgorithm;
}

/**
 * Verify request
 */
export interface VerifyRequest {
  /** Key ID */
  keyId: string;
  /** Original message (base64) */
  message: string;
  /** Signature (base64) */
  signature: string;
  /** Hash algorithm */
  hashAlgorithm?: HashAlgorithm;
  /** Key version */
  keyVersion?: number;
}

/**
 * Hash request
 */
export interface HashRequest {
  /** Data to hash (base64) */
  data: string;
  /** Hash algorithm */
  algorithm: HashAlgorithm;
}

/**
 * HMAC request
 */
export interface HMACRequest {
  /** Key ID */
  keyId: string;
  /** Message to authenticate (base64) */
  message: string;
  /** Hash algorithm */
  hashAlgorithm?: HashAlgorithm;
}

/**
 * Verify HMAC request
 */
export interface VerifyHMACRequest {
  /** Key ID */
  keyId: string;
  /** Original message (base64) */
  message: string;
  /** HMAC value (base64) */
  hmac: string;
  /** Hash algorithm */
  hashAlgorithm?: HashAlgorithm;
  /** Key version */
  keyVersion?: number;
}

/**
 * Generate random request
 */
export interface GenerateRandomRequest {
  /** Number of random bytes to generate */
  numBytes: number;
}

/**
 * Generate data key request
 */
export interface GenerateDataKeyRequest {
  /** Key encryption key ID */
  keyId: string;
  /** Algorithm for the data key */
  algorithm?: KMSKeyAlgorithm;
  /** Key size in bits */
  keySize?: number;
  /** Additional context (base64) */
  context?: string;
}

/**
 * Generate wrapped data key request
 */
export interface GenerateWrappedDataKeyRequest {
  /** Wrapping key ID */
  wrappingKeyId: string;
  /** Wrapping algorithm */
  wrappingAlgorithm?: WrappingAlgorithm;
  /** Algorithm for the data key */
  keyAlgorithm?: KMSKeyAlgorithm;
  /** Key size in bits */
  keySize?: number;
  /** Additional context (base64) */
  context?: string;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface KMSStatus {
  /** Whether the operation succeeded */
  success: boolean;
  /** Status message */
  message: string;
  /** Error details if failed */
  error?: {
    code: string;
    message: string;
    metadata?: Record<string, string>;
  };
}

/**
 * Generate key response
 */
export interface GenerateKeyResponse {
  /** Operation status */
  status: KMSStatus;
  /** Key handle */
  key?: KMSKeyHandle;
  /** Key metadata */
  metadata?: KMSKeyMetadata;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Import key response
 */
export interface ImportKeyResponse {
  /** Operation status */
  status: KMSStatus;
  /** Key handle */
  key?: KMSKeyHandle;
  /** Key metadata */
  metadata?: KMSKeyMetadata;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Get key response
 */
export interface GetKeyResponse {
  /** Key handle */
  key: KMSKeyHandle;
  /** Key metadata */
  metadata: KMSKeyMetadata;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * List keys response
 */
export interface ListKeysResponse {
  /** Key handles */
  keys: KMSKeyHandle[];
  /** Next cursor for pagination */
  nextCursor?: string;
  /** Whether there are more results */
  hasMore: boolean;
  /** Total count */
  totalCount: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Delete key response
 */
export interface DeleteKeyResponse {
  /** Operation status */
  status: KMSStatus;
  /** Key ID */
  keyId: string;
  /** New key status */
  keyStatus: KeyStatus;
  /** Scheduled deletion date (unix epoch) */
  deletionDate?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Rotate key response
 */
export interface RotateKeyResponse {
  /** Operation status */
  status: KMSStatus;
  /** Key ID */
  keyId: string;
  /** Old version number */
  oldVersion: number;
  /** New version number */
  newVersion: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Update key status response
 */
export interface UpdateKeyStatusResponse {
  /** Operation status */
  status: KMSStatus;
  /** Key ID */
  keyId: string;
  /** Key version */
  version: number;
  /** New key status */
  keyStatus: KeyStatus;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Export key response
 */
export interface ExportKeyResponse {
  /** Operation status */
  status: KMSStatus;
  /** Key ID */
  keyId: string;
  /** Export format */
  format: KeyExportFormat;
  /** Wrapping key ID */
  wrappingKeyId?: string;
  /** Wrapping algorithm */
  wrappingAlgorithm?: WrappingAlgorithm;
  /** Wrapped key material (base64) */
  wrappedMaterial: string;
  /** Key version */
  version: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Get key versions response
 */
export interface GetKeyVersionsResponse {
  /** Key ID */
  keyId: string;
  /** Key versions */
  versions: KMSKeyVersionInfo[];
  /** Next cursor for pagination */
  nextCursor?: string;
  /** Whether there are more results */
  hasMore: boolean;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Encrypt response
 */
export interface EncryptResponse {
  /** Operation status */
  status: KMSStatus;
  /** Key ID */
  keyId: string;
  /** Key version used */
  keyVersion: number;
  /** Ciphertext (base64) */
  ciphertext: string;
  /** Nonce (base64) */
  nonce?: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Decrypt response
 */
export interface DecryptResponse {
  /** Operation status */
  status: KMSStatus;
  /** Key ID */
  keyId: string;
  /** Key version used */
  keyVersion: number;
  /** Plaintext (base64) */
  plaintext: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Sign response
 */
export interface SignResponse {
  /** Operation status */
  status: KMSStatus;
  /** Key ID */
  keyId: string;
  /** Key version used */
  keyVersion: number;
  /** Signature (base64) */
  signature: string;
  /** Hash algorithm used */
  hashAlgorithm: HashAlgorithm;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Verify response
 */
export interface VerifyResponse {
  /** Operation status */
  status: KMSStatus;
  /** Key ID */
  keyId: string;
  /** Key version used */
  keyVersion: number;
  /** Whether the signature is valid */
  valid: boolean;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Hash response
 */
export interface HashResponse {
  /** Operation status */
  status: KMSStatus;
  /** Hash algorithm used */
  algorithm: HashAlgorithm;
  /** Hash value (base64) */
  hash: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * HMAC response
 */
export interface HMACResponse {
  /** Operation status */
  status: KMSStatus;
  /** Key ID */
  keyId: string;
  /** Key version used */
  keyVersion: number;
  /** HMAC value (base64) */
  hmac: string;
  /** Hash algorithm used */
  hashAlgorithm: HashAlgorithm;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Verify HMAC response
 */
export interface VerifyHMACResponse {
  /** Operation status */
  status: KMSStatus;
  /** Key ID */
  keyId: string;
  /** Key version used */
  keyVersion: number;
  /** Whether the HMAC is valid */
  valid: boolean;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Generate random response
 */
export interface GenerateRandomResponse {
  /** Operation status */
  status: KMSStatus;
  /** Random bytes (base64) */
  randomBytes: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Generate data key response
 */
export interface GenerateDataKeyResponse {
  /** Operation status */
  status: KMSStatus;
  /** Plaintext key (base64) */
  plaintextKey: string;
  /** Encrypted key (base64) */
  encryptedKey: string;
  /** Key encryption key ID */
  keyId: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Generate wrapped data key response
 */
export interface GenerateWrappedDataKeyResponse {
  /** Operation status */
  status: KMSStatus;
  /** Wrapped key (base64) */
  wrappedKey: string;
  /** Wrapping key ID */
  wrappingKeyId: string;
  /** Wrapping algorithm */
  wrappingAlgorithm: WrappingAlgorithm;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Backend status response
 */
export interface BackendStatusResponse {
  /** Operation status */
  status: KMSStatus;
  /** Backend type (e.g., 'tpm', 'pkcs11', 'software') */
  backendType: string;
  /** Backend status description */
  backendStatus: string;
  /** Device path (if applicable) */
  device?: string;
  /** Region (if applicable) */
  region?: string;
  /** Key ID (if applicable) */
  keyId?: string;
  /** PCR banks available */
  pcrBanks?: string[];
  /** PCR registers */
  pcrRegisters?: number[];
  /** Backend capabilities */
  capabilities?: Record<string, boolean>;
  /** Timestamp (unix epoch) */
  timestamp: number;
}
