/**
 * Virtual TPM (vTPM) Types
 *
 * Types for vTPM bundle management operations.
 * Based on pkg/api/grpc/proto/vtpm.proto
 */

// =============================================================================
// Enums
// =============================================================================

/**
 * Bundle creation mode
 */
export type BundleMode =
  | 'UNSPECIFIED'
  | 'TEMPLATE'
  | 'PRE_ASSIGNED';

/**
 * EK key algorithm
 */
export type EKAlgorithm =
  | 'UNSPECIFIED'
  | 'RSA'
  | 'ECC';

/**
 * Maps each bundle mode to the string the REST handler parses
 * (pkg/vtpm/types.go); UNSPECIFIED is sent as no mode, so the server default
 * applies.
 */
export const BUNDLE_MODE_WIRE_NAMES: Readonly<Record<BundleMode, string | undefined>> = {
  UNSPECIFIED: undefined,
  TEMPLATE: 'template',
  PRE_ASSIGNED: 'pre-assigned',
};

/**
 * Maps each EK algorithm to the string the REST handler parses; UNSPECIFIED
 * is sent as no algorithm, so the server default applies.
 */
export const EK_ALGORITHM_WIRE_NAMES: Readonly<Record<EKAlgorithm, string | undefined>> = {
  UNSPECIFIED: undefined,
  RSA: 'RSA',
  ECC: 'ECC',
};

// =============================================================================
// Data Types
// =============================================================================

/**
 * EK certificate information
 */
export interface EKCertInfo {
  /** Subject name */
  subject: string;
  /** Issuer name */
  issuer: string;
  /** Serial number */
  serialNumber: string;
  /** Not valid before */
  notBefore: string;
  /** Not valid after */
  notAfter: string;
  /** Fingerprint */
  fingerprint: string;
}

/**
 * Secure Boot key information
 */
export interface SecureBootKeyInfo {
  /** PK fingerprint */
  pkFingerprint: string;
  /** KEK fingerprint */
  kekFingerprint: string;
  /** DB fingerprint */
  dbFingerprint: string;
  /** Owner GUID */
  ownerGuid: string;
}

/**
 * Secure Boot key paths
 */
export interface SecureBootKeyPaths {
  /** Keys directory */
  dir: string;
  /** PK private key path */
  pkKey: string;
  /** PK certificate path */
  pkCrt: string;
  /** KEK private key path */
  kekKey: string;
  /** KEK certificate path */
  kekCrt: string;
  /** DB private key path */
  dbKey: string;
  /** DB certificate path */
  dbCrt: string;
}

/**
 * TPM state files
 */
export interface TPMState {
  /** State directory */
  stateDir: string;
  /** Permanent state file */
  permallFile: string;
  /** Volatile state file */
  volatileFile: string;
}

/**
 * OVMF NVRAM state
 */
export interface OVMFState {
  /** NVRAM file path */
  nvramFile: string;
}

/**
 * Bundle manifest
 */
export interface VTPMManifest {
  /** Manifest version */
  version: string;
  /** Bundle ID */
  id: string;
  /** Bundle mode */
  mode: BundleMode;
  /** Hostname */
  hostname: string;
  /** Creation timestamp */
  createdAt: string;
  /** EK certificate info */
  ekCertificate?: EKCertInfo;
  /** EK algorithm */
  ekAlgorithm: EKAlgorithm;
  /** EK TPM handle */
  ekHandle: number;
  /** Secure Boot enabled */
  secureBootEnabled: boolean;
  /** Secure Boot key info */
  secureBootKeys?: SecureBootKeyInfo;
  /** File checksums */
  checksums?: Record<string, string>;
  /** Labels */
  labels?: Record<string, string>;
  /** Cloned from template ID */
  clonedFrom?: string;
}

/**
 * Complete vTPM bundle
 */
export interface VTPMBundle {
  /** Bundle ID */
  id: string;
  /** Bundle mode */
  mode: BundleMode;
  /** Manifest */
  manifest: VTPMManifest;
  /** TPM state */
  tpmState: TPMState;
  /** OVMF state */
  ovmfState: OVMFState;
  /** Secure Boot key paths */
  secureBootKeys?: SecureBootKeyPaths;
  /** Creation timestamp */
  createdAt: string;
  /** Cloned from template ID */
  clonedFrom?: string;
}

/**
 * vTPM template (no identity)
 */
export interface VTPMTemplate {
  /** Template ID */
  id: string;
  /** Description */
  description: string;
  /** TPM state directory */
  tpmStateDir: string;
  /** NVRAM path */
  nvramPath: string;
  /** Secure Boot keys directory */
  secureBootKeysDir?: string;
  /** EK algorithm */
  ekAlgorithm: EKAlgorithm;
  /** Secure Boot enabled */
  secureBootEnabled: boolean;
  /** Creation timestamp */
  createdAt: string;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Create bundle options
 */
export interface CreateBundleOptions {
  /** Bundle mode */
  mode?: BundleMode;
  /** Hostname */
  hostname?: string;
  /** EK algorithm */
  ekAlgorithm?: EKAlgorithm;
  /** Enable Secure Boot */
  secureBootEnabled?: boolean;
  /** Labels */
  labels?: Record<string, string>;
  /** Template ID to use */
  templateId?: string;
  /** Device profile ID to bind this bundle to (uint64 as string) */
  deviceProfileId?: string;
}

/**
 * Create bundle request
 */
export interface CreateBundleRequest {
  /** Options */
  options: CreateBundleOptions;
}

/**
 * Get bundle request
 */
export interface GetBundleRequest {
  /** Bundle ID */
  id: string;
}

/**
 * Delete bundle request
 */
export interface DeleteBundleRequest {
  /** Bundle ID */
  id: string;
}

/**
 * List bundles options
 */
export interface ListBundleOptions {
  /** Filter by mode */
  mode?: BundleMode;
  /** Filter by labels */
  labels?: Record<string, string>;
  /** Limit */
  limit?: number;
  /** Offset */
  offset?: number;
  /** Filter bundles bound to this device profile (uint64 as string) */
  deviceProfileId?: string;
}

/**
 * List bundles request
 */
export interface ListBundlesRequest {
  /** Options */
  options?: ListBundleOptions;
}

/**
 * Create template options
 */
export interface CreateTemplateOptions {
  /** Template ID */
  id: string;
  /** Description */
  description?: string;
  /** EK algorithm */
  ekAlgorithm?: EKAlgorithm;
  /** Enable Secure Boot */
  secureBootEnabled?: boolean;
}

/**
 * Create template request
 */
export interface CreateTemplateRequest {
  /** Options */
  options: CreateTemplateOptions;
}

/**
 * Get template request
 */
export interface GetTemplateRequest {
  /** Template ID */
  id: string;
}

/**
 * Delete template request
 */
export interface DeleteTemplateRequest {
  /** Template ID */
  id: string;
}

/**
 * Clone options
 */
export interface CloneOptions {
  /** Template ID to clone */
  templateId: string;
  /** Hostname for new bundle */
  hostname: string;
  /** Labels */
  labels?: Record<string, string>;
}

/**
 * Clone template request
 */
export interface CloneTemplateRequest {
  /** Options */
  options: CloneOptions;
}

/**
 * Export bundle request
 */
export interface ExportBundleRequest {
  /** Bundle ID */
  id: string;
}

/**
 * Validate bundle request
 */
export interface ValidateBundleRequest {
  /** Bundle ID */
  id: string;
}

/**
 * Get bundle path request
 */
export interface GetBundlePathRequest {
  /** Bundle ID */
  id: string;
}

/**
 * Get TPM socket path request
 */
export interface GetTPMSocketPathRequest {
  /** Bundle ID */
  id: string;
}

/**
 * Get NVRAM path request
 */
export interface GetNVRAMPathRequest {
  /** Bundle ID */
  id: string;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface VTPMStatus {
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

/** EK certificate summary as pkg/webservice/v1/rest/vtpm EKCertInfoResponse sends it. */
export interface WireEKCertInfo {
  subject: string;
  issuer: string;
  serial_number: string;
  not_before?: string;
  not_after?: string;
  fingerprint: string;
}

/** Secure Boot key fingerprints as SecureBootKeyInfoResponse sends them. */
export interface WireSecureBootKeyInfo {
  pk_fingerprint: string;
  kek_fingerprint: string;
  db_fingerprint: string;
  owner_guid: string;
}

/** Secure Boot key paths as SecureBootKeyPathsResponse sends them. */
export interface WireSecureBootKeyPaths {
  dir: string;
  pk_key: string;
  pk_crt: string;
  kek_key: string;
  kek_crt: string;
  db_key: string;
  db_crt: string;
}

/** Bundle manifest as ManifestResponse sends it. */
export interface WireManifest {
  version: string;
  id: string;
  /** Wire mode spelling, e.g. 'pre-assigned'; createBundle accepts it back. */
  mode: string;
  hostname?: string;
  created_at?: string;
  ek_certificate?: WireEKCertInfo;
  /** Wire EK algorithm spelling; createBundle accepts it back. */
  ek_algorithm: string;
  ek_handle: number;
  secure_boot_enabled: boolean;
  secure_boot_keys?: WireSecureBootKeyInfo;
  checksums?: Record<string, string>;
  labels?: Record<string, string>;
  cloned_from?: string;
  /**
   * The bound device profile (a uint64). JSON.parse reads it as a number, so
   * an ID above 2^53 - 1 is not exact here; listBundles filters by the digits.
   */
  device_profile_id?: number;
}

/**
 * Create bundle response: the bundle itself, exactly as the daemon writes it
 * (pkg/webservice/v1/rest/vtpm BundleResponse) — flat, snake_case, with the
 * omitempty fields optional. There is no status wrapper; a failure is the
 * ApiResponse error.
 */
export interface CreateBundleResponse {
  /** Generated bundle ID */
  id: string;
  /** Wire mode spelling, e.g. 'pre-assigned' */
  mode: string;
  manifest?: WireManifest;
  tpm_state?: {
    state_dir: string;
    permall_file: string;
    volatile_file?: string;
  };
  ovmf_state?: {
    nvram_file: string;
  };
  secure_boot_keys?: WireSecureBootKeyPaths;
  created_at?: string;
  cloned_from?: string;
}

/**
 * Get bundle response
 */
export interface GetBundleResponse {
  /** Bundle */
  bundle: VTPMBundle;
}

/**
 * Delete bundle response
 */
export interface DeleteBundleResponse {
  /** Operation status */
  status: VTPMStatus;
}

/**
 * List bundles response
 */
export interface ListBundlesResponse {
  /** Bundles */
  bundles: VTPMBundle[];
  /** Total count */
  total: number;
}

/**
 * Create template response: the template itself, exactly as the daemon writes
 * it (pkg/webservice/v1/rest/vtpm TemplateResponse). There is no status
 * wrapper; a failure is the ApiResponse error.
 */
export interface CreateTemplateResponse {
  /** Template ID */
  id: string;
  description?: string;
  tpm_state_dir: string;
  nvram_path: string;
  secure_boot_keys_dir?: string;
  /** Wire EK algorithm spelling */
  ek_algorithm: string;
  secure_boot_enabled: boolean;
  created_at?: string;
}

/**
 * Get template response
 */
export interface GetTemplateResponse {
  /** Template */
  template: VTPMTemplate;
}

/**
 * Delete template response
 */
export interface DeleteTemplateResponse {
  /** Operation status */
  status: VTPMStatus;
}

/**
 * List templates response
 */
export interface ListTemplatesResponse {
  /** Templates */
  templates: VTPMTemplate[];
}

/**
 * Clone template response
 */
export interface CloneTemplateResponse {
  /** Operation status */
  status: VTPMStatus;
  /** Created bundle */
  bundle?: VTPMBundle;
}

/**
 * Validate bundle response
 */
export interface ValidateBundleResponse {
  /** Operation status */
  status: VTPMStatus;
  /** Whether valid */
  valid: boolean;
  /** Validation errors */
  errors?: string[];
}

/**
 * Get bundle path response
 */
export interface GetBundlePathResponse {
  /** Bundle path */
  path: string;
}

/**
 * Get TPM socket path response
 */
export interface GetTPMSocketPathResponse {
  /** TPM socket path */
  path: string;
}

/**
 * Get NVRAM path response
 */
export interface GetNVRAMPathResponse {
  /** NVRAM path */
  path: string;
}

// =============================================================================
// vTPM Instance Types (Runtime Management)
// =============================================================================

/**
 * vTPM instance status
 */
export type VTPMInstanceStatus = 'STOPPED' | 'STARTING' | 'RUNNING' | 'STOPPING' | 'ERROR';

/**
 * vTPM instance configuration
 */
export interface VTPMInstanceConfig {
  /** TPM version (e.g., "2.0") */
  tpmVersion?: string;
  /** State path for persistent storage */
  statePath?: string;
  /** Socket path for TPM communication */
  socketPath?: string;
  /** Enable logging */
  enableLogging?: boolean;
  /** Log level */
  logLevel?: string;
}

/**
 * vTPM instance representing a running virtual TPM
 */
export interface VTPMInstance {
  /** Unique instance identifier */
  id: string;
  /** Associated profile ID */
  profileId?: number;
  /** State path for persistent storage */
  statePath: string;
  /** EK certificate fingerprint */
  ekFingerprint: string;
  /** Creation timestamp */
  createdAt: string;
  /** Whether the instance is currently running */
  isRunning: boolean;
  /** Instance status */
  status?: VTPMInstanceStatus;
  /** Process ID if running */
  pid?: number;
  /** Socket path for TPM communication */
  socketPath?: string;
  /** Last started timestamp */
  lastStartedAt?: string;
  /** Last stopped timestamp */
  lastStoppedAt?: string;
  /** Error message if in error state */
  errorMessage?: string;
}

/**
 * vTPM instance status details
 */
export interface VTPMInstanceStatusDetails {
  /** Instance ID */
  id: string;
  /** Whether running */
  isRunning: boolean;
  /** Instance status */
  status: VTPMInstanceStatus;
  /** Process ID if running */
  pid?: number;
  /** Memory usage in bytes */
  memoryUsage?: number;
  /** CPU usage percentage */
  cpuUsage?: number;
  /** Uptime in seconds */
  uptime?: number;
  /** Last health check timestamp */
  lastHealthCheck?: string;
  /** Health check status */
  healthy?: boolean;
}

// =============================================================================
// vTPM Instance Request Types
// =============================================================================

/**
 * Create vTPM instance request
 */
export interface CreateVTPMInstanceRequest {
  /** Associated profile ID (optional) */
  profileId?: number;
  /** Instance configuration */
  config?: VTPMInstanceConfig;
}

/**
 * Get vTPM instance request
 */
export interface GetVTPMInstanceRequest {
  /** Instance ID */
  id: string;
}

/**
 * Get vTPM instance by profile request
 */
export interface GetVTPMInstanceByProfileRequest {
  /** Profile ID */
  profileId: number;
}

/**
 * List vTPM instances request
 */
export interface ListVTPMInstancesRequest {
  /** Filter by profile ID */
  profileId?: number;
  /** Filter by running status */
  isRunning?: boolean;
  /** Filter by status */
  status?: VTPMInstanceStatus;
  /** Page number (1-indexed) */
  page?: number;
  /** Items per page */
  pageSize?: number;
}

/**
 * Delete vTPM instance request
 */
export interface DeleteVTPMInstanceRequest {
  /** Instance ID */
  id: string;
  /** Force delete even if running */
  force?: boolean;
}

/**
 * Start vTPM instance request
 */
export interface StartVTPMInstanceRequest {
  /** Instance ID */
  id: string;
}

/**
 * Stop vTPM instance request
 */
export interface StopVTPMInstanceRequest {
  /** Instance ID */
  id: string;
  /** Force stop */
  force?: boolean;
}

/**
 * Get vTPM instance status request
 */
export interface GetVTPMInstanceStatusRequest {
  /** Instance ID */
  id: string;
}

/**
 * Get vTPM instance EK certificate request
 */
export interface GetVTPMInstanceEKCertRequest {
  /** Instance ID */
  id: string;
  /** Certificate format (pem or der) */
  format?: 'pem' | 'der';
}

/**
 * Get vTPM instance EK fingerprint request
 */
export interface GetVTPMInstanceEKFingerprintRequest {
  /** Instance ID */
  id: string;
  /** Hash algorithm for fingerprint */
  algorithm?: 'sha256' | 'sha384' | 'sha512';
}

// =============================================================================
// vTPM Instance Response Types
// =============================================================================

/**
 * vTPM instance pagination info
 */
export interface VTPMInstancePaginationInfo {
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
 * Create vTPM instance response
 */
export interface CreateVTPMInstanceResponse {
  /** Operation status */
  status: VTPMStatus;
  /** Created instance */
  instance?: VTPMInstance;
}

/**
 * Get vTPM instance response
 */
export interface GetVTPMInstanceResponse {
  /** Instance */
  instance: VTPMInstance;
}

/**
 * Get vTPM instance by profile response
 */
export interface GetVTPMInstanceByProfileResponse {
  /** Instance */
  instance: VTPMInstance;
}

/**
 * List vTPM instances response
 */
export interface ListVTPMInstancesResponse {
  /** Instances */
  instances: VTPMInstance[];
  /** Pagination info */
  pagination: VTPMInstancePaginationInfo;
}

/**
 * Delete vTPM instance response
 */
export interface DeleteVTPMInstanceResponse {
  /** Operation status */
  status: VTPMStatus;
}

/**
 * Start vTPM instance response
 */
export interface StartVTPMInstanceResponse {
  /** Operation status */
  status: VTPMStatus;
  /** Updated instance */
  instance?: VTPMInstance;
}

/**
 * Stop vTPM instance response
 */
export interface StopVTPMInstanceResponse {
  /** Operation status */
  status: VTPMStatus;
  /** Updated instance */
  instance?: VTPMInstance;
}

/**
 * Get vTPM instance status response
 */
export interface GetVTPMInstanceStatusResponse {
  /** Status details */
  statusDetails: VTPMInstanceStatusDetails;
}

/**
 * Get vTPM instance EK certificate response
 */
export interface GetVTPMInstanceEKCertResponse {
  /** Certificate in requested format */
  certificate: string;
  /** Certificate format */
  format: 'pem' | 'der';
  /** Subject name */
  subject: string;
  /** Issuer name */
  issuer: string;
  /** Serial number */
  serialNumber: string;
  /** Not valid before */
  notBefore: string;
  /** Not valid after */
  notAfter: string;
}

/**
 * Get vTPM instance EK fingerprint response
 */
export interface GetVTPMInstanceEKFingerprintResponse {
  /** Fingerprint value */
  fingerprint: string;
  /** Hash algorithm used */
  algorithm: 'sha256' | 'sha384' | 'sha512';
}
