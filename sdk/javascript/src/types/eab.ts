/**
 * EAB (External Account Binding) Types
 *
 * Types for EAB credential management operations.
 * EAB credentials are used for ACME certificate enrollment.
 */

// =============================================================================
// Enums
// =============================================================================

/**
 * EAB credential status
 */
export type EABCredentialStatus = 'ACTIVE' | 'REVOKED' | 'EXPIRED' | 'USED';

// =============================================================================
// Data Types
// =============================================================================

/**
 * EAB credential
 */
/**
 * EAB credential id. The server mints a uint64 (UnixNano-based) that protojson
 * writes as a decimal string; a JavaScript number above 2^53 loses digits, so
 * carry the id as that string end to end. A number is still accepted for
 * small ids.
 */
export type EABCredentialId = string | number;

export interface EABCredential {
  /** Unique identifier */
  id: EABCredentialId;
  /** Key identifier for ACME binding */
  keyId: string;
  /** HMAC key for signing */
  hmacKey: string;
  /** Associated profile ID */
  profileId: number;
  /** Tenant identifier */
  tenantId: string;
  /** Expiration timestamp */
  expiresAt: string;
  /** Credential status */
  status: EABCredentialStatus;
  /** Creation timestamp */
  createdAt: string;
  /** Last update timestamp */
  updatedAt: string;
}

/**
 * EAB credential summary (without sensitive HMAC key)
 */
export interface EABCredentialSummary {
  /** Unique identifier */
  id: EABCredentialId;
  /** Key identifier for ACME binding */
  keyId: string;
  /** Associated profile ID */
  profileId: number;
  /** Tenant identifier */
  tenantId: string;
  /** Expiration timestamp */
  expiresAt: string;
  /** Credential status */
  status: EABCredentialStatus;
  /** Creation timestamp */
  createdAt: string;
  /** Last update timestamp */
  updatedAt: string;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Create EAB credential request
 */
export interface CreateEABCredentialRequest {
  /** Profile ID to associate with */
  profileId: number;
  /** Tenant identifier */
  tenantId: string;
  /** Expiration time in seconds (optional) */
  expiresInSeconds?: number;
}

/**
 * Get EAB credential request
 */
export interface GetEABCredentialRequest {
  /** Credential ID */
  id: EABCredentialId;
}

/**
 * Get EAB credential by key ID request
 */
export interface GetEABCredentialByKeyIdRequest {
  /** Key identifier */
  keyId: string;
}

/**
 * List EAB credentials request
 */
export interface ListEABCredentialsRequest {
  /** Filter by profile ID */
  profileId?: number;
  /** Filter by tenant ID */
  tenantId?: string;
  /** Filter by status */
  status?: EABCredentialStatus;
  /** Page number (1-indexed) */
  page?: number;
  /** Items per page */
  pageSize?: number;
}

/**
 * Revoke EAB credential request
 */
export interface RevokeEABCredentialRequest {
  /** Credential ID */
  id: EABCredentialId;
}

/**
 * Validate EAB credential request
 */
export interface ValidateEABCredentialRequest {
  /** Key identifier */
  keyId: string;
  /** HMAC key */
  hmacKey: string;
}

/**
 * Delete EAB credential request
 */
export interface DeleteEABCredentialRequest {
  /** Credential ID */
  id: EABCredentialId;
}

/**
 * Get EAB QR code request
 */
export interface GetEABQRCodeRequest {
  /** Credential ID */
  id: EABCredentialId;
  /** QR code size in pixels (optional) */
  size?: number;
}

/**
 * Get enrollment URL request
 */
export interface GetEnrollmentURLRequest {
  /** Credential ID */
  id: EABCredentialId;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface EABStatus {
  /** Whether operation succeeded */
  success: boolean;
  /** Status message */
  message: string;
  /** Error details */
  error?: {
    code: string;
    message: string;
    metadata?: Record<string, string>;
  };
}

/**
 * Pagination info
 */
export interface EABPaginationInfo {
  /** Current page */
  page: number;
  /** Items per page */
  pageSize: number;
  /** Total items */
  totalItems: number;
  /** Total pages */
  totalPages: number;
}

/**
 * Create EAB credential response
 */
export interface CreateEABCredentialResponse {
  /** Operation status */
  status: EABStatus;
  /** Created credential (includes HMAC key only on creation) */
  credential?: EABCredential;
}

/**
 * Get EAB credential response
 */
export interface GetEABCredentialResponse {
  /** Credential (without HMAC key for security) */
  credential: EABCredentialSummary;
}

/**
 * Get EAB credential by key ID response
 */
export interface GetEABCredentialByKeyIdResponse {
  /** Credential (without HMAC key for security) */
  credential: EABCredentialSummary;
}

/**
 * List EAB credentials response
 */
export interface ListEABCredentialsResponse {
  /** Credentials (without HMAC keys) */
  credentials: EABCredentialSummary[];
  /** Pagination info */
  pagination: EABPaginationInfo;
}

/**
 * Revoke EAB credential response
 */
export interface RevokeEABCredentialResponse {
  /** Operation status */
  status: EABStatus;
}

/**
 * Validate EAB credential response: the platform.v1
 * ValidateEABCredentialResponse message as the server sends it in protojson.
 */
export interface ValidateEABCredentialResponse {
  /** Whether the key identifier and HMAC key match a usable credential */
  valid: boolean;
  /** The matched credential, without its HMAC key */
  credential?: EABCredentialSummary;
  /** Why the credential is not valid */
  errorMessage?: string;
  /** Response timestamp */
  timestamp?: string;
}

/**
 * Delete EAB credential response
 */
export interface DeleteEABCredentialResponse {
  /** Operation status */
  status: EABStatus;
}

/**
 * Get EAB QR code response: the platform.v1 GetEABCredentialQRCodeResponse
 * message as the server sends it in protojson.
 */
export interface GetEABQRCodeResponse {
  /** The PNG image bytes, base64-encoded (protojson bytes encoding) */
  qrCode: string;
  /** Image MIME type (e.g. "image/png") */
  contentType: string;
  /** Response timestamp */
  timestamp?: string;
}

/**
 * Get enrollment URL response
 */
export interface GetEnrollmentURLResponse {
  /** Enrollment URL */
  url: string;
  /** URL expiration timestamp */
  expiresAt: string;
}
