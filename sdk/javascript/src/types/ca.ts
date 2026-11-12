/**
 * Certificate Authority (CA) Types
 *
 * Types for CA operations including certificate management, CRL, and bundles.
 * Based on pkg/api/grpc/proto/ca.proto
 */

// =============================================================================
// Enums
// =============================================================================

/**
 * Revocation reason for certificate revocation
 */
export type RevocationReason =
  | 'UNSPECIFIED'
  | 'KEY_COMPROMISE'
  | 'CA_COMPROMISE'
  | 'AFFILIATION_CHANGED'
  | 'SUPERSEDED'
  | 'CESSATION_OF_OPERATION'
  | 'CERTIFICATE_HOLD'
  | 'REMOVE_FROM_CRL'
  | 'PRIVILEGE_WITHDRAWN'
  | 'AA_COMPROMISE';

/**
 * Certificate type
 */
export type CertificateType =
  | 'UNSPECIFIED'
  | 'SERVER'
  | 'CLIENT'
  | 'CA'
  | 'CODE_SIGNING'
  | 'EMAIL';

/**
 * Certificate status
 */
export type CertificateStatus =
  | 'UNSPECIFIED'
  | 'VALID'
  | 'REVOKED'
  | 'EXPIRED'
  | 'PENDING';

/**
 * Key algorithm
 */
export type KeyAlgorithm =
  | 'UNSPECIFIED'
  | 'RSA_2048'
  | 'RSA_3072'
  | 'RSA_4096'
  | 'ECDSA_P256'
  | 'ECDSA_P384'
  | 'ECDSA_P521'
  | 'ED25519'
  | 'DILITHIUM2'
  | 'DILITHIUM3'
  | 'DILITHIUM5';

// =============================================================================
// Data Types
// =============================================================================

/**
 * Certificate subject information
 */
export interface Subject {
  /** Common name (CN) */
  commonName: string;
  /** Organization (O) */
  organization?: string;
  /** Organizational unit (OU) */
  organizationalUnit?: string;
  /** Country (C) */
  country?: string;
  /** Province/State (ST) */
  province?: string;
  /** Locality/City (L) */
  locality?: string;
  /** Street address */
  address?: string;
  /** Postal code */
  postalCode?: string;
}

/**
 * Subject Alternative Names (SANs)
 */
export interface SubjectAlternativeNames {
  /** DNS names */
  dnsNames?: string[];
  /** IP addresses */
  ipAddresses?: string[];
  /** Email addresses */
  emailAddresses?: string[];
  /** URIs */
  uris?: string[];
}

/**
 * Key store information
 */
export interface KeyStoreInfo {
  /** Store type (e.g., 'pkcs11', 'tpm', 'software') */
  type: string;
  /** Whether the store is available */
  available: boolean;
  /** List of capabilities */
  capabilities: string[];
}

/**
 * CA information
 */
export interface CAInfo {
  /** CA common name */
  commonName: string;
  /** Whether the CA is initialized */
  isInitialized: boolean;
  /** Whether this is an intermediate CA */
  isIntermediate: boolean;
  /** Root certificate summary */
  rootCert?: CertificateSummary;
  /** Intermediate certificates */
  intermediates: CertificateSummary[];
  /** Available key stores */
  keyStores: KeyStoreInfo[];
  /** Default algorithm for new certificates */
  defaultAlgorithm: string;
  /** Default validity period in days */
  defaultValidityDays: number;
}

/**
 * Full certificate data
 */
export interface Certificate {
  /** Certificate serial number (hex) */
  serial: string;
  /** Subject information */
  subject: Subject;
  /** Issuer common name */
  issuer: string;
  /** Not valid before timestamp */
  notBefore: string;
  /** Not valid after timestamp */
  notAfter: string;
  /** Certificate status */
  status: CertificateStatus;
  /** Key algorithm */
  keyAlgorithm: KeyAlgorithm;
  /** Signature algorithm */
  signatureAlgorithm: string;
  /** Whether this is a CA certificate */
  isCA: boolean;
  /** Maximum path length for CA certificates */
  maxPathLen: number;
  /** Subject alternative names */
  sans?: SubjectAlternativeNames;
  /** Key usage extensions */
  keyUsage: string[];
  /** Extended key usage extensions */
  extKeyUsage: string[];
  /** PEM-encoded certificate */
  pem?: string;
  /** DER-encoded certificate (base64) */
  der?: string;
  /** SHA-256 fingerprint */
  fingerprintSha256: string;
  /** Additional metadata */
  metadata?: Record<string, string>;
}

/**
 * Certificate summary for lists
 */
export interface CertificateSummary {
  /** Certificate serial number (hex) */
  serial: string;
  /** Common name */
  commonName: string;
  /** Issuer common name */
  issuer: string;
  /** Not valid before timestamp */
  notBefore: string;
  /** Not valid after timestamp */
  notAfter: string;
  /** Certificate status */
  status: CertificateStatus;
  /** Key algorithm */
  keyAlgorithm: KeyAlgorithm;
}

/**
 * Revoked certificate entry
 */
export interface RevokedCertEntry {
  /** Certificate serial number */
  serial: string;
  /** Revocation timestamp */
  revocationTime: string;
  /** Revocation reason */
  reason: RevocationReason;
}

/**
 * Certificate Revocation List (CRL)
 */
export interface CRL {
  /** CRL data (base64) */
  data: string;
  /** Last update timestamp */
  lastUpdate: string;
  /** Next update timestamp */
  nextUpdate: string;
  /** Number of revoked certificates */
  revokedCount: number;
  /** List of revoked certificates */
  revokedCerts: RevokedCertEntry[];
}

/**
 * CA certificate bundle
 */
export interface CABundle {
  /** PEM-encoded bundle */
  pem: string;
  /** Certificate summaries in the bundle */
  certificates: CertificateSummary[];
  /** Number of certificates in the bundle */
  certCount: number;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Certificate request for issuance
 */
export interface CertificateRequest {
  /** Subject information */
  subject: Subject;
  /** Subject alternative names */
  sans?: SubjectAlternativeNames;
  /** Validity period in days */
  validDays?: number;
  /** Key algorithm */
  keyAlgorithm?: KeyAlgorithm;
  /** Key store type to use */
  storeType?: string;
  /** Key usage extensions */
  keyUsage?: string[];
  /** Extended key usage extensions */
  extKeyUsage?: string[];
  /** Whether this is a CA certificate */
  isCA?: boolean;
  /** Maximum path length for CA certificates */
  maxPathLen?: number;
  /** Certificate type */
  certificateType?: CertificateType;
  /** Additional metadata */
  metadata?: Record<string, string>;
}

/**
 * Certificate revocation request
 */
export interface RevokeCertificateRequest {
  /** Certificate serial number */
  serial: string;
  /** Revocation reason */
  reason: RevocationReason;
  /** Whether to delete the keys */
  deleteKeys?: boolean;
}

/**
 * Certificate renewal request
 */
export interface RenewCertificateRequest {
  /** Certificate serial number */
  serial: string;
  /** New validity period in days */
  validDays?: number;
  /** Whether to preserve existing SANs */
  preserveSans?: boolean;
  /** New SANs (if not preserving) */
  newSans?: SubjectAlternativeNames;
}

/**
 * Certificate verification request
 */
export interface VerifyCertificateRequest {
  /** Certificate in PEM format */
  certificatePem?: string;
  /** Certificate in DER format (base64) */
  certificateDer?: string;
  /** Whether to verify revocation status */
  verifyRevocation?: boolean;
  /** Whether to verify expiration */
  verifyExpiration?: boolean;
  /** Additional trusted roots (PEM, base64) */
  trustedRoots?: string[];
}

/**
 * Request to certify, for code signing, the KMS key a CSR names
 * (POST /v1/ca/sign-csr; the caller's token needs ca:sign-csr)
 */
export interface SignCSRRequest {
  /** PKCS#10 certificate signing request in PEM format */
  csrPem: string;
  /** Validity period in days (the CA default when absent) */
  validDays?: number;
}

/**
 * List certificates request options
 */
export interface ListCertificatesOptions {
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
  /** Sort field */
  sortBy?: string;
  /** Ascending sort */
  ascending?: boolean;
  /** Filter by status */
  statusFilter?: CertificateStatus;
  /** Filter by type */
  typeFilter?: CertificateType;
  /** Filter by issuer */
  issuerFilter?: string;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * CA info response
 */
export interface GetCAInfoResponse {
  /** CA information */
  caInfo: CAInfo;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Issue certificate response
 */
export interface IssueCertificateResponse {
  /** Operation status */
  status: OperationStatus;
  /** Issued certificate */
  certificate?: Certificate;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Get certificate response
 */
export interface GetCertificateResponse {
  /** Certificate data */
  certificate: Certificate;
  /** Response timestamp */
  timestamp: string;
}

/**
 * List certificates response
 */
export interface ListCertificatesResponse {
  /** Certificate summaries */
  certificates: CertificateSummary[];
  /** Pagination info */
  pagination: CAPaginationResponse;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Revoke certificate response
 */
export interface RevokeCertificateResponse {
  /** Operation status */
  status: OperationStatus;
  /** Certificate serial number */
  serial: string;
  /** New certificate status */
  certificateStatus: CertificateStatus;
  /** Revocation timestamp */
  revokedAt: string;
  /** Revocation reason */
  reason: RevocationReason;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Renew certificate response
 */
export interface RenewCertificateResponse {
  /** Operation status */
  status: OperationStatus;
  /** Old certificate */
  oldCertificate?: Certificate;
  /** New certificate */
  newCertificate?: Certificate;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Verify certificate response
 */
export interface VerifyCertificateResponse {
  /** Operation status */
  status: OperationStatus;
  /** Whether the certificate is valid */
  valid: boolean;
  /** Certificate chain (serials) */
  chain: string[];
  /** Validation errors */
  errors: string[];
  /** Validation warnings */
  warnings: string[];
  /** Response timestamp */
  timestamp: string;
}

/**
 * Get CRL response
 */
export interface GetCRLResponse {
  /** CRL data */
  crl: CRL;
  /** Response timestamp */
  timestamp: string;
}

/**
 * Get CA bundle response
 */
export interface GetCABundleResponse {
  /** CA bundle */
  bundle: CABundle;
  /** Response timestamp */
  timestamp: string;
}

// =============================================================================
// Common Types (re-exported for convenience)
// =============================================================================

/**
 * Operation status
 */
export interface OperationStatus {
  /** Whether the operation succeeded */
  success: boolean;
  /** Status message */
  message: string;
  /** Error details if failed */
  error?: ErrorDetail;
}

/**
 * Error detail
 */
export interface ErrorDetail {
  /** Error code */
  code: string;
  /** Error message */
  message: string;
  /** Additional metadata */
  metadata?: Record<string, string>;
}

/**
 * Pagination response
 */
export interface CAPaginationResponse {
  /** Current page */
  page: number;
  /** Page size */
  pageSize: number;
  /** Total pages */
  totalPages: number;
  /** Total items */
  totalItems: number;
}
