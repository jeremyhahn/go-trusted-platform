/**
 * IDevID Service Types
 *
 * Types for device identity management operations (IDevID and IAK).
 * Based on pkg/api/grpc/proto/idevid.proto
 */

// =============================================================================
// Enums
// =============================================================================

/**
 * Device key algorithm
 */
export type DeviceKeyAlgorithm =
  | 'UNSPECIFIED'
  | 'ECDSA_P256'
  | 'ECDSA_P384'
  | 'RSA_2048'
  | 'RSA_3072';

/**
 * Certificate storage type
 */
export type CertStorageType =
  | 'UNSPECIFIED'
  | 'NVRAM'
  | 'FILESYSTEM';

// =============================================================================
// Configuration Types
// =============================================================================

/**
 * IDevID configuration
 */
export interface IDevIDConfig {
  /** Key algorithm */
  algorithm?: DeviceKeyAlgorithm;
  /** TPM handle */
  handle?: number;
  /** TPM hierarchy */
  hierarchy?: 'endorsement' | 'owner' | 'platform';
  /** Subject common name */
  subjectCommonName?: string;
  /** Subject organization */
  subjectOrganization?: string;
  /** Certificate storage type */
  storage?: CertStorageType;
  /** Storage path */
  storagePath?: string;
  /** NVRAM index */
  nvIndex?: number;
  /** Owner authorization */
  ownerAuth?: string;
  /** Endorsement authorization */
  endorsementAuth?: string;
  /** Overwrite existing key */
  overwrite?: boolean;
}

/**
 * IAK configuration
 */
export interface IAKConfig {
  /** Key algorithm */
  algorithm?: DeviceKeyAlgorithm;
  /** TPM handle */
  handle?: number;
  /** TPM hierarchy */
  hierarchy?: 'endorsement' | 'owner' | 'platform';
  /** Subject common name */
  subjectCommonName?: string;
  /** Subject organization */
  subjectOrganization?: string;
  /** Certificate storage type */
  storage?: CertStorageType;
  /** Storage path */
  storagePath?: string;
  /** NVRAM index */
  nvIndex?: number;
  /** Owner authorization */
  ownerAuth?: string;
  /** Endorsement authorization */
  endorsementAuth?: string;
  /** Overwrite existing key */
  overwrite?: boolean;
}

/**
 * CSR template
 */
export interface CSRTemplate {
  /** Common name */
  commonName?: string;
  /** Organization */
  organization?: string;
  /** Organizational unit */
  organizationalUnit?: string;
  /** Country */
  country?: string;
  /** Province/State */
  province?: string;
  /** Locality/City */
  locality?: string;
  /** Email addresses */
  emailAddresses?: string[];
  /** DNS names */
  dnsNames?: string[];
  /** TCG device attributes */
  tcgAttributes?: TCGDeviceAttributes;
}

// =============================================================================
// Data Types
// =============================================================================

/**
 * TCG device attributes
 */
export interface TCGDeviceAttributes {
  /** TPM manufacturer */
  tpmManufacturer?: string;
  /** TPM model */
  tpmModel?: string;
  /** TPM version */
  tpmVersion?: string;
  /** Platform manufacturer */
  platformManufacturer?: string;
  /** Platform model */
  platformModel?: string;
  /** Platform version */
  platformVersion?: string;
  /** Platform serial */
  platformSerial?: string;
}

/**
 * Device identity certificate
 */
export interface DeviceIdentityCertificate {
  /** PEM-encoded certificate */
  pem?: string;
  /** DER-encoded certificate (base64) */
  der?: string;
  /** Key type (IDevID, IAK, LDevID, LAK) */
  keyType: string;
  /** TPM handle */
  tpmHandle: number;
  /** Issue timestamp */
  issuedAt: string;
  /** Expiration timestamp */
  expiresAt: string;
  /** Issuer common name */
  issuerCn: string;
  /** Subject common name */
  subjectCn: string;
  /** Serial number (hex) */
  serialNumber: string;
  /** SHA-256 fingerprint (hex) */
  fingerprint: string;
  /** Key algorithm */
  keyAlgorithm: string;
  /** Signature algorithm */
  signatureAlgorithm: string;
  /** Key size in bits */
  keySize: number;
}

/**
 * Device key information
 */
export interface DeviceKeyInfo {
  /** TPM handle */
  handle: number;
  /** Key algorithm */
  algorithm: DeviceKeyAlgorithm;
  /** Public key (PEM, base64) */
  publicKeyPem?: string;
  /** Creation timestamp */
  createdAt: string;
  /** Has certificate */
  hasCertificate: boolean;
  /** Certificate info */
  certificateInfo?: DeviceIdentityCertificate;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Generate IDevID request
 */
export interface GenerateIDevIDRequest {
  /** Configuration */
  config?: IDevIDConfig;
}

/**
 * Get IDevID info request
 */
export interface GetIDevIDInfoRequest {}

/**
 * Has IDevID request
 */
export interface HasIDevIDRequest {}

/**
 * Delete IDevID request
 */
export interface DeleteIDevIDRequest {}

/**
 * Generate IAK request
 */
export interface GenerateIAKRequest {
  /** Configuration */
  config?: IAKConfig;
}

/**
 * Get IAK info request
 */
export interface GetIAKInfoRequest {}

/**
 * Has IAK request
 */
export interface HasIAKRequest {}

/**
 * Delete IAK request
 */
export interface DeleteIAKRequest {}

/**
 * Create IDevID CSR request
 */
export interface CreateIDevIDCSRRequest {
  /** CSR template */
  template?: CSRTemplate;
}

/**
 * Create IAK CSR request
 */
export interface CreateIAKCSRRequest {
  /** CSR template */
  template?: CSRTemplate;
}

/**
 * Install IDevID certificate request
 */
export interface InstallIDevIDCertificateRequest {
  /** Certificate (PEM, base64) */
  certificatePem: string;
}

/**
 * Install IAK certificate request
 */
export interface InstallIAKCertificateRequest {
  /** Certificate (PEM, base64) */
  certificatePem: string;
}

/**
 * Get IDevID certificate request
 */
export interface GetIDevIDCertificateRequest {}

/**
 * Get IAK certificate request
 */
export interface GetIAKCertificateRequest {}

/**
 * Delete IDevID certificate request
 */
export interface DeleteIDevIDCertificateRequest {}

/**
 * Delete IAK certificate request
 */
export interface DeleteIAKCertificateRequest {}

/**
 * Get device attributes request
 */
export interface GetDeviceAttributesRequest {}

/**
 * Flush transient contexts request
 */
export interface FlushTransientContextsRequest {}

/**
 * Activate credential request
 */
export interface ActivateCredentialRequest {
  /** Credential blob (base64) */
  credentialBlob: string;
  /** Secret (base64) */
  secret: string;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface IDevIDStatus {
  /** Whether succeeded */
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
 * Generate IDevID response
 */
export interface GenerateIDevIDResponse {
  /** Operation status */
  status: IDevIDStatus;
}

/**
 * Get IDevID info response
 */
export interface GetIDevIDInfoResponse {
  /** Key info */
  keyInfo: DeviceKeyInfo;
}

/**
 * Has IDevID response
 */
export interface HasIDevIDResponse {
  /** Whether exists */
  exists: boolean;
}

/**
 * Delete IDevID response
 */
export interface DeleteIDevIDResponse {
  /** Operation status */
  status: IDevIDStatus;
}

/**
 * Generate IAK response
 */
export interface GenerateIAKResponse {
  /** Operation status */
  status: IDevIDStatus;
}

/**
 * Get IAK info response
 */
export interface GetIAKInfoResponse {
  /** Key info */
  keyInfo: DeviceKeyInfo;
}

/**
 * Has IAK response
 */
export interface HasIAKResponse {
  /** Whether exists */
  exists: boolean;
}

/**
 * Delete IAK response
 */
export interface DeleteIAKResponse {
  /** Operation status */
  status: IDevIDStatus;
}

/**
 * Create IDevID CSR response
 */
export interface CreateIDevIDCSRResponse {
  /** Operation status */
  status: IDevIDStatus;
  /** CSR (PEM, base64) */
  csrPem?: string;
}

/**
 * Create IAK CSR response
 */
export interface CreateIAKCSRResponse {
  /** Operation status */
  status: IDevIDStatus;
  /** CSR (PEM, base64) */
  csrPem?: string;
}

/**
 * Install IDevID certificate response
 */
export interface InstallIDevIDCertificateResponse {
  /** Operation status */
  status: IDevIDStatus;
}

/**
 * Install IAK certificate response
 */
export interface InstallIAKCertificateResponse {
  /** Operation status */
  status: IDevIDStatus;
}

/**
 * Get IDevID certificate response
 */
export interface GetIDevIDCertificateResponse {
  /** Certificate */
  certificate: DeviceIdentityCertificate;
}

/**
 * Get IAK certificate response
 */
export interface GetIAKCertificateResponse {
  /** Certificate */
  certificate: DeviceIdentityCertificate;
}

/**
 * Delete IDevID certificate response
 */
export interface DeleteIDevIDCertificateResponse {
  /** Operation status */
  status: IDevIDStatus;
}

/**
 * Delete IAK certificate response
 */
export interface DeleteIAKCertificateResponse {
  /** Operation status */
  status: IDevIDStatus;
}

/**
 * Get device attributes response
 */
export interface GetDeviceAttributesResponse {
  /** Device attributes */
  attributes: TCGDeviceAttributes;
}

/**
 * Flush transient contexts response
 */
export interface FlushTransientContextsResponse {
  /** Operation status */
  status: IDevIDStatus;
  /** Number of flushed contexts */
  flushedCount: number;
}

/**
 * Activate credential response
 */
export interface ActivateCredentialResponse {
  /** Operation status */
  status: IDevIDStatus;
  /** Decrypted secret (base64) */
  decryptedSecret?: string;
}
