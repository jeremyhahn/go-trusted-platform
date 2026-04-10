/**
 * QuicBaaS Security Types - Part 1
 *
 * Types for QuicBaaS security services including authentication, key management,
 * secrets management, cryptographic operations, and dynamic secrets.
 */

// =============================================================================
// Common Enums and Types
// =============================================================================

/**
 * Authentication method type
 */
export type QuicBaaSAuthMethod =
  | 'password'
  | 'token'
  | 'certificate'
  | 'ldap'
  | 'oidc'
  | 'apikey';

/**
 * Token type for authentication
 */
export type TokenType =
  | 'access'
  | 'refresh'
  | 'service';

/**
 * Key algorithm for QuicBaaS KMS
 */
export type QuicBaaSKeyAlgorithm =
  | 'AES_128'
  | 'AES_256'
  | 'RSA_2048'
  | 'RSA_4096'
  | 'ECDSA_P256'
  | 'ECDSA_P384'
  | 'ED25519';

/**
 * Key type classification
 */
export type QuicBaaSKeyType =
  | 'symmetric'
  | 'asymmetric'
  | 'hmac';

/**
 * Key status in QuicBaaS KMS
 */
export type QuicBaaSKeyStatus =
  | 'active'
  | 'inactive'
  | 'pending_deletion'
  | 'destroyed';

/**
 * Secret type classification
 */
export type SecretType =
  | 'kv'
  | 'password'
  | 'certificate'
  | 'ssh_key'
  | 'api_key'
  | 'database'
  | 'custom';

/**
 * Hash algorithm for crypto operations
 */
export type QuicBaaSHashAlgorithm =
  | 'SHA256'
  | 'SHA384'
  | 'SHA512'
  | 'SHA3_256'
  | 'SHA3_512'
  | 'BLAKE2b'
  | 'BLAKE3';

/**
 * Signature algorithm
 */
export type SignatureAlgorithm =
  | 'RSA_PKCS1_SHA256'
  | 'RSA_PKCS1_SHA384'
  | 'RSA_PKCS1_SHA512'
  | 'RSA_PSS_SHA256'
  | 'RSA_PSS_SHA384'
  | 'RSA_PSS_SHA512'
  | 'ECDSA_SHA256'
  | 'ECDSA_SHA384'
  | 'ED25519';

/**
 * Encryption algorithm for crypto service
 */
export type EncryptionAlgorithm =
  | 'AES_GCM'
  | 'AES_CBC'
  | 'AES_CTR'
  | 'CHACHA20_POLY1305'
  | 'RSA_OAEP_SHA256'
  | 'RSA_OAEP_SHA384'
  | 'RSA_OAEP_SHA512';

/**
 * Dynamic secret backend type
 */
export type DynamicSecretBackend =
  | 'database'
  | 'aws'
  | 'gcp'
  | 'azure'
  | 'kubernetes'
  | 'ssh'
  | 'pki'
  | 'consul'
  | 'nomad'
  | 'ldap';

/**
 * Database type for dynamic secrets
 */
export type DatabaseType =
  | 'postgresql'
  | 'mysql'
  | 'mongodb'
  | 'redis'
  | 'elasticsearch'
  | 'cassandra'
  | 'mssql'
  | 'oracle';

// =============================================================================
// Common Data Types
// =============================================================================

/**
 * Operation status for QuicBaaS responses
 */
export interface QuicBaaSSecurityStatus {
  /** Whether the operation succeeded */
  success: boolean;
  /** Status message */
  message: string;
  /** Error details if failed */
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}

/**
 * Pagination information
 */
export interface PaginationInfo {
  /** Total number of items */
  total: number;
  /** Current page */
  page: number;
  /** Items per page */
  pageSize: number;
  /** Whether there are more pages */
  hasMore: boolean;
  /** Cursor for next page */
  nextCursor?: string;
}

// =============================================================================
// Authentication Types
// =============================================================================

/**
 * Login request
 */
export interface LoginRequest {
  /** Authentication method */
  method: QuicBaaSAuthMethod;
  /** Username or identifier */
  username?: string;
  /** Password (for password auth) */
  password?: string;
  /** Token (for token auth) */
  token?: string;
  /** Certificate (for certificate auth, PEM format) */
  certificate?: string;
  /** Private key (for certificate auth, PEM format) */
  privateKey?: string;
  /** OIDC provider */
  oidcProvider?: string;
  /** OIDC code */
  oidcCode?: string;
  /** LDAP domain */
  ldapDomain?: string;
  /** API key */
  apiKey?: string;
  /** Additional metadata */
  metadata?: Record<string, string>;
}

/**
 * Login response
 */
export interface LoginResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Access token */
  accessToken?: string;
  /** Refresh token */
  refreshToken?: string;
  /** Token type (e.g., 'Bearer') */
  tokenType?: string;
  /** Access token expiration (unix epoch) */
  expiresAt?: number;
  /** Refresh token expiration (unix epoch) */
  refreshExpiresAt?: number;
  /** User ID */
  userId?: string;
  /** User roles */
  roles?: string[];
  /** User permissions */
  permissions?: string[];
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Logout request
 */
export interface LogoutRequest {
  /** Token to invalidate */
  token?: string;
  /** Invalidate all tokens for user */
  invalidateAll?: boolean;
}

/**
 * Logout response
 */
export interface LogoutResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Number of tokens invalidated */
  tokensInvalidated?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Refresh token request
 */
export interface RefreshTokenRequest {
  /** Refresh token */
  refreshToken: string;
}

/**
 * Refresh token response
 */
export interface RefreshTokenResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** New access token */
  accessToken?: string;
  /** New refresh token (if rotated) */
  refreshToken?: string;
  /** Access token expiration (unix epoch) */
  expiresAt?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Validate token request
 */
export interface ValidateTokenRequest {
  /** Token to validate */
  token: string;
}

/**
 * Validate token response
 */
export interface ValidateTokenResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Whether the token is valid */
  valid: boolean;
  /** User ID */
  userId?: string;
  /** Token expiration (unix epoch) */
  expiresAt?: number;
  /** Token scopes */
  scopes?: string[];
  /** Token metadata */
  metadata?: Record<string, string>;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Create API key request
 */
export interface CreateApiKeyRequest {
  /** API key name */
  name: string;
  /** Description */
  description?: string;
  /** Expiration (unix epoch, optional) */
  expiresAt?: number;
  /** Scopes for the API key */
  scopes?: string[];
  /** IP whitelist */
  allowedIps?: string[];
  /** Rate limit (requests per minute) */
  rateLimit?: number;
  /** Metadata */
  metadata?: Record<string, string>;
}

/**
 * Create API key response
 */
export interface CreateApiKeyResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** API key ID */
  keyId?: string;
  /** API key value (only returned once on creation) */
  apiKey?: string;
  /** API key name */
  name?: string;
  /** Expiration (unix epoch) */
  expiresAt?: number;
  /** Creation timestamp (unix epoch) */
  createdAt?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Revoke API key request
 */
export interface RevokeApiKeyRequest {
  /** API key ID */
  keyId: string;
}

/**
 * Revoke API key response
 */
export interface RevokeApiKeyResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Revoked API key ID */
  keyId?: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

// =============================================================================
// QuicBaaS KMS Types
// =============================================================================

/**
 * Key metadata for QuicBaaS KMS
 */
export interface QuicBaaSKeyMetadata {
  /** Key ID */
  keyId: string;
  /** Key name */
  name: string;
  /** Key description */
  description?: string;
  /** Key algorithm */
  algorithm: QuicBaaSKeyAlgorithm;
  /** Key type */
  keyType: QuicBaaSKeyType;
  /** Key status */
  status: QuicBaaSKeyStatus;
  /** Current version */
  version: number;
  /** Whether the key is exportable */
  exportable: boolean;
  /** Whether the key is rotatable */
  rotatable: boolean;
  /** Creation timestamp (unix epoch) */
  createdAt: number;
  /** Last update timestamp (unix epoch) */
  updatedAt: number;
  /** Last rotation timestamp (unix epoch) */
  lastRotatedAt?: number;
  /** Next scheduled rotation (unix epoch) */
  nextRotationAt?: number;
  /** Key tags */
  tags?: Record<string, string>;
  /** Owner */
  owner?: string;
}

/**
 * Generate key request for QuicBaaS KMS
 */
export interface QuicBaaSGenerateKeyRequest {
  /** Key name */
  name: string;
  /** Key algorithm */
  algorithm: QuicBaaSKeyAlgorithm;
  /** Key description */
  description?: string;
  /** Whether the key is exportable */
  exportable?: boolean;
  /** Whether automatic rotation is enabled */
  autoRotate?: boolean;
  /** Rotation interval in days */
  rotationIntervalDays?: number;
  /** Key tags */
  tags?: Record<string, string>;
}

/**
 * Generate key response for QuicBaaS KMS
 */
export interface QuicBaaSGenerateKeyResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Key metadata */
  key?: QuicBaaSKeyMetadata;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Import key request for QuicBaaS KMS
 */
export interface QuicBaaSImportKeyRequest {
  /** Key name */
  name: string;
  /** Key material (base64 encoded) */
  keyMaterial: string;
  /** Key algorithm */
  algorithm: QuicBaaSKeyAlgorithm;
  /** Key description */
  description?: string;
  /** Whether the key is exportable */
  exportable?: boolean;
  /** Key tags */
  tags?: Record<string, string>;
}

/**
 * Import key response for QuicBaaS KMS
 */
export interface QuicBaaSImportKeyResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Key metadata */
  key?: QuicBaaSKeyMetadata;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Get key request for QuicBaaS KMS
 */
export interface QuicBaaSGetKeyRequest {
  /** Key ID */
  keyId: string;
  /** Specific version (optional) */
  version?: number;
}

/**
 * Get key response for QuicBaaS KMS
 */
export interface QuicBaaSGetKeyResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Key metadata */
  key?: QuicBaaSKeyMetadata;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * List keys request for QuicBaaS KMS
 */
export interface QuicBaaSListKeysRequest {
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
  /** Filter by status */
  status?: QuicBaaSKeyStatus;
  /** Filter by algorithm */
  algorithm?: QuicBaaSKeyAlgorithm;
  /** Filter by name prefix */
  namePrefix?: string;
  /** Filter by tags */
  tags?: Record<string, string>;
}

/**
 * List keys response for QuicBaaS KMS
 */
export interface QuicBaaSListKeysResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Key list */
  keys?: QuicBaaSKeyMetadata[];
  /** Pagination information */
  pagination?: PaginationInfo;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Rotate key request for QuicBaaS KMS
 */
export interface QuicBaaSRotateKeyRequest {
  /** Key ID */
  keyId: string;
}

/**
 * Rotate key response for QuicBaaS KMS
 */
export interface QuicBaaSRotateKeyResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Key ID */
  keyId?: string;
  /** Old version */
  oldVersion?: number;
  /** New version */
  newVersion?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Delete key request for QuicBaaS KMS
 */
export interface QuicBaaSDeleteKeyRequest {
  /** Key ID */
  keyId: string;
  /** Force immediate deletion */
  force?: boolean;
  /** Pending deletion window in days */
  pendingWindowDays?: number;
}

/**
 * Delete key response for QuicBaaS KMS
 */
export interface QuicBaaSDeleteKeyResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Key ID */
  keyId?: string;
  /** New key status */
  keyStatus?: QuicBaaSKeyStatus;
  /** Scheduled deletion date (unix epoch) */
  scheduledDeletionAt?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * KMS encrypt request for QuicBaaS KMS
 */
export interface QuicBaaSKMSEncryptRequest {
  /** Key ID */
  keyId: string;
  /** Plaintext (base64 encoded) */
  plaintext: string;
  /** Additional authenticated data (base64 encoded) */
  context?: string;
}

/**
 * KMS encrypt response for QuicBaaS KMS
 */
export interface QuicBaaSKMSEncryptResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Ciphertext (base64 encoded) */
  ciphertext?: string;
  /** Key ID used */
  keyId?: string;
  /** Key version used */
  keyVersion?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * KMS decrypt request for QuicBaaS KMS
 */
export interface QuicBaaSKMSDecryptRequest {
  /** Key ID */
  keyId: string;
  /** Ciphertext (base64 encoded) */
  ciphertext: string;
  /** Additional authenticated data (base64 encoded) */
  context?: string;
  /** Key version (optional) */
  keyVersion?: number;
}

/**
 * KMS decrypt response for QuicBaaS KMS
 */
export interface QuicBaaSKMSDecryptResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Plaintext (base64 encoded) */
  plaintext?: string;
  /** Key ID used */
  keyId?: string;
  /** Key version used */
  keyVersion?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

// =============================================================================
// Secrets Service Types
// =============================================================================

/**
 * Secret metadata
 */
export interface SecretMetadata {
  /** Secret path */
  path: string;
  /** Secret name */
  name: string;
  /** Secret type */
  type: SecretType;
  /** Current version */
  version: number;
  /** Creation timestamp (unix epoch) */
  createdAt: number;
  /** Last update timestamp (unix epoch) */
  updatedAt: number;
  /** Expiration timestamp (unix epoch, optional) */
  expiresAt?: number;
  /** Secret tags */
  tags?: Record<string, string>;
  /** Owner */
  owner?: string;
  /** Whether the secret is deleted */
  deleted: boolean;
  /** Number of versions */
  versionCount: number;
}

/**
 * Secret version information
 */
export interface SecretVersion {
  /** Version number */
  version: number;
  /** Creation timestamp (unix epoch) */
  createdAt: number;
  /** Created by */
  createdBy?: string;
  /** Whether this version is deleted */
  deleted: boolean;
  /** Deletion timestamp (unix epoch) */
  deletedAt?: number;
}

/**
 * Create secret request
 */
export interface CreateSecretRequest {
  /** Secret path */
  path: string;
  /** Secret data (key-value pairs) */
  data: Record<string, string>;
  /** Secret type */
  type?: SecretType;
  /** Expiration timestamp (unix epoch) */
  expiresAt?: number;
  /** Secret tags */
  tags?: Record<string, string>;
  /** Custom metadata */
  metadata?: Record<string, string>;
}

/**
 * Create secret response
 */
export interface CreateSecretResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Secret metadata */
  secret?: SecretMetadata;
  /** Version number */
  version?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Get secret request
 */
export interface GetSecretRequest {
  /** Secret path */
  path: string;
  /** Specific version (optional, defaults to latest) */
  version?: number;
}

/**
 * Get secret response
 */
export interface GetSecretResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Secret data */
  data?: Record<string, string>;
  /** Secret metadata */
  metadata?: SecretMetadata;
  /** Version number */
  version?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Update secret request
 */
export interface UpdateSecretRequest {
  /** Secret path */
  path: string;
  /** Secret data (key-value pairs) */
  data: Record<string, string>;
  /** Check-and-set version (optional, for optimistic locking) */
  cas?: number;
}

/**
 * Update secret response
 */
export interface UpdateSecretResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Secret metadata */
  secret?: SecretMetadata;
  /** New version number */
  version?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Delete secret request
 */
export interface DeleteSecretRequest {
  /** Secret path */
  path: string;
  /** Specific versions to delete (optional, deletes all if not specified) */
  versions?: number[];
  /** Permanent deletion */
  permanent?: boolean;
}

/**
 * Delete secret response
 */
export interface DeleteSecretResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Deleted secret path */
  path?: string;
  /** Deleted versions */
  deletedVersions?: number[];
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * List secrets request
 */
export interface ListSecretsRequest {
  /** Path prefix */
  pathPrefix?: string;
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
  /** Filter by type */
  type?: SecretType;
  /** Filter by tags */
  tags?: Record<string, string>;
  /** Include deleted secrets */
  includeDeleted?: boolean;
}

/**
 * List secrets response
 */
export interface ListSecretsResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Secret metadata list */
  secrets?: SecretMetadata[];
  /** Pagination information */
  pagination?: PaginationInfo;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Get secret version request
 */
export interface GetSecretVersionRequest {
  /** Secret path */
  path: string;
  /** Version number */
  version: number;
}

/**
 * Get secret version response
 */
export interface GetSecretVersionResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Secret data */
  data?: Record<string, string>;
  /** Version information */
  versionInfo?: SecretVersion;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * List secret versions request
 */
export interface ListSecretVersionsRequest {
  /** Secret path */
  path: string;
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
}

/**
 * List secret versions response
 */
export interface ListSecretVersionsResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Secret path */
  path?: string;
  /** Version list */
  versions?: SecretVersion[];
  /** Pagination information */
  pagination?: PaginationInfo;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Rotate secret request
 */
export interface RotateSecretRequest {
  /** Secret path */
  path: string;
  /** New secret data (optional, auto-generates if not provided) */
  newData?: Record<string, string>;
}

/**
 * Rotate secret response
 */
export interface RotateSecretResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Secret metadata */
  secret?: SecretMetadata;
  /** Old version number */
  oldVersion?: number;
  /** New version number */
  newVersion?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

// =============================================================================
// Crypto Service Types
// =============================================================================

/**
 * Encrypt request for crypto service
 */
export interface CryptoEncryptRequest {
  /** Key ID (optional, uses transit key if not specified) */
  keyId?: string;
  /** Plaintext (base64 encoded) */
  plaintext: string;
  /** Encryption algorithm */
  algorithm?: EncryptionAlgorithm;
  /** Additional authenticated data (base64 encoded) */
  aad?: string;
  /** Nonce/IV (base64 encoded, auto-generated if not specified) */
  nonce?: string;
}

/**
 * Encrypt response for crypto service
 */
export interface CryptoEncryptResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Ciphertext (base64 encoded) */
  ciphertext?: string;
  /** Nonce/IV used (base64 encoded) */
  nonce?: string;
  /** Authentication tag (base64 encoded, for AEAD ciphers) */
  tag?: string;
  /** Key ID used */
  keyId?: string;
  /** Key version used */
  keyVersion?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Decrypt request for crypto service
 */
export interface CryptoDecryptRequest {
  /** Key ID */
  keyId?: string;
  /** Ciphertext (base64 encoded) */
  ciphertext: string;
  /** Encryption algorithm */
  algorithm?: EncryptionAlgorithm;
  /** Additional authenticated data (base64 encoded) */
  aad?: string;
  /** Nonce/IV (base64 encoded) */
  nonce?: string;
  /** Authentication tag (base64 encoded, for AEAD ciphers) */
  tag?: string;
  /** Key version */
  keyVersion?: number;
}

/**
 * Decrypt response for crypto service
 */
export interface CryptoDecryptResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Plaintext (base64 encoded) */
  plaintext?: string;
  /** Key ID used */
  keyId?: string;
  /** Key version used */
  keyVersion?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Sign request for crypto service
 */
export interface CryptoSignRequest {
  /** Key ID */
  keyId: string;
  /** Data to sign (base64 encoded) */
  data: string;
  /** Signature algorithm */
  algorithm?: SignatureAlgorithm;
  /** Whether the data is already hashed */
  prehashed?: boolean;
}

/**
 * Sign response for crypto service
 */
export interface CryptoSignResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Signature (base64 encoded) */
  signature?: string;
  /** Key ID used */
  keyId?: string;
  /** Key version used */
  keyVersion?: number;
  /** Algorithm used */
  algorithm?: SignatureAlgorithm;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Verify request for crypto service
 */
export interface CryptoVerifyRequest {
  /** Key ID */
  keyId: string;
  /** Original data (base64 encoded) */
  data: string;
  /** Signature (base64 encoded) */
  signature: string;
  /** Signature algorithm */
  algorithm?: SignatureAlgorithm;
  /** Whether the data is already hashed */
  prehashed?: boolean;
  /** Key version */
  keyVersion?: number;
}

/**
 * Verify response for crypto service
 */
export interface CryptoVerifyResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Whether the signature is valid */
  valid: boolean;
  /** Key ID used */
  keyId?: string;
  /** Key version used */
  keyVersion?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Hash request for crypto service
 */
export interface CryptoHashRequest {
  /** Data to hash (base64 encoded) */
  data: string;
  /** Hash algorithm */
  algorithm: QuicBaaSHashAlgorithm;
}

/**
 * Hash response for crypto service
 */
export interface CryptoHashResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Hash value (base64 encoded) */
  hash?: string;
  /** Algorithm used */
  algorithm?: QuicBaaSHashAlgorithm;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Generate random request for crypto service
 */
export interface CryptoGenerateRandomRequest {
  /** Number of bytes to generate */
  length: number;
  /** Output format */
  format?: 'base64' | 'hex';
}

/**
 * Generate random response for crypto service
 */
export interface CryptoGenerateRandomResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Random data */
  randomData?: string;
  /** Output format */
  format?: 'base64' | 'hex';
  /** Timestamp (unix epoch) */
  timestamp: number;
}

// =============================================================================
// Dynamic Secrets Service Types
// =============================================================================

/**
 * Dynamic secret configuration
 */
export interface DynamicSecretConfig {
  /** Configuration ID */
  configId: string;
  /** Configuration name */
  name: string;
  /** Backend type */
  backend: DynamicSecretBackend;
  /** Database type (if backend is database) */
  databaseType?: DatabaseType;
  /** Connection string or endpoint */
  connection: string;
  /** Default TTL in seconds */
  defaultTtl: number;
  /** Maximum TTL in seconds */
  maxTtl: number;
  /** Creation template (for database credentials) */
  creationStatements?: string[];
  /** Revocation template (for database credentials) */
  revocationStatements?: string[];
  /** Rotation template */
  rotationStatements?: string[];
  /** Whether the configuration is enabled */
  enabled: boolean;
  /** Creation timestamp (unix epoch) */
  createdAt: number;
  /** Last update timestamp (unix epoch) */
  updatedAt: number;
  /** Configuration metadata */
  metadata?: Record<string, string>;
}

/**
 * Generated dynamic credential
 */
export interface DynamicCredential {
  /** Credential ID */
  credentialId: string;
  /** Configuration ID */
  configId: string;
  /** Username */
  username?: string;
  /** Password */
  password?: string;
  /** Connection string */
  connectionString?: string;
  /** Access key (for cloud providers) */
  accessKey?: string;
  /** Secret key (for cloud providers) */
  secretKey?: string;
  /** Token (for some backends) */
  token?: string;
  /** Certificate (PEM format, for PKI backend) */
  certificate?: string;
  /** Private key (PEM format, for PKI backend) */
  privateKey?: string;
  /** Expiration timestamp (unix epoch) */
  expiresAt: number;
  /** Creation timestamp (unix epoch) */
  createdAt: number;
  /** Whether the credential is revoked */
  revoked: boolean;
  /** Additional data */
  additionalData?: Record<string, string>;
}

/**
 * Generate dynamic secret request
 */
export interface GenerateDynamicSecretRequest {
  /** Configuration ID or name */
  configId: string;
  /** TTL in seconds (optional, uses default if not specified) */
  ttl?: number;
  /** Role name (for database backends) */
  role?: string;
  /** Additional parameters */
  parameters?: Record<string, string>;
}

/**
 * Generate dynamic secret response
 */
export interface GenerateDynamicSecretResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Generated credential */
  credential?: DynamicCredential;
  /** Lease ID */
  leaseId?: string;
  /** Lease duration in seconds */
  leaseDuration?: number;
  /** Whether the lease is renewable */
  renewable?: boolean;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Revoke dynamic secret request
 */
export interface RevokeDynamicSecretRequest {
  /** Credential ID or lease ID */
  credentialId: string;
}

/**
 * Revoke dynamic secret response
 */
export interface RevokeDynamicSecretResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Revoked credential ID */
  credentialId?: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Configure dynamic secret backend request
 */
export interface ConfigureDynamicSecretRequest {
  /** Configuration name */
  name: string;
  /** Backend type */
  backend: DynamicSecretBackend;
  /** Database type (if backend is database) */
  databaseType?: DatabaseType;
  /** Connection string or endpoint */
  connection: string;
  /** Username for connection */
  username?: string;
  /** Password for connection */
  password?: string;
  /** Default TTL in seconds */
  defaultTtl?: number;
  /** Maximum TTL in seconds */
  maxTtl?: number;
  /** Creation statements */
  creationStatements?: string[];
  /** Revocation statements */
  revocationStatements?: string[];
  /** Rotation statements */
  rotationStatements?: string[];
  /** Whether to enable the configuration */
  enabled?: boolean;
  /** Configuration metadata */
  metadata?: Record<string, string>;
}

/**
 * Configure dynamic secret backend response
 */
export interface ConfigureDynamicSecretResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Configuration */
  config?: DynamicSecretConfig;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * List dynamic secret configurations request
 */
export interface ListDynamicSecretConfigsRequest {
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
  /** Filter by backend type */
  backend?: DynamicSecretBackend;
  /** Filter by enabled status */
  enabled?: boolean;
}

/**
 * List dynamic secret configurations response
 */
export interface ListDynamicSecretConfigsResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Configuration list */
  configs?: DynamicSecretConfig[];
  /** Pagination information */
  pagination?: PaginationInfo;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Delete dynamic secret configuration request
 */
export interface DeleteDynamicSecretConfigRequest {
  /** Configuration ID */
  configId: string;
  /** Force deletion (revokes all active credentials) */
  force?: boolean;
}

/**
 * Delete dynamic secret configuration response
 */
export interface DeleteDynamicSecretConfigResponse {
  /** Operation status */
  status: QuicBaaSSecurityStatus;
  /** Deleted configuration ID */
  configId?: string;
  /** Number of revoked credentials */
  revokedCredentials?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}
