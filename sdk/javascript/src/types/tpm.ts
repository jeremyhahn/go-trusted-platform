/**
 * TPM (Trusted Platform Module) Types
 *
 * Types for TPM operations including key management, sealing, and attestation.
 * Based on pkg/api/grpc/proto/tpm.proto
 */

import type { KeyAlgorithm } from './ca.js';

// =============================================================================
// Enums
// =============================================================================

/**
 * TPM version, spelled as the server serialises the proto `TPMVersion` enum.
 */
export type TPMVersion =
  | 'TPM_VERSION_UNSPECIFIED'
  | 'TPM_VERSION_1_2'
  | 'TPM_VERSION_2_0';

/**
 * PCR bank (hash algorithm), in the short form the SDK accepts on requests.
 * Request methods translate it to the proto name; see `PCRBankName`.
 */
export type PCRBank =
  | 'UNSPECIFIED'
  | 'SHA1'
  | 'SHA256'
  | 'SHA384'
  | 'SHA512'
  | 'SM3_256';

/**
 * PCR bank as the server serialises the proto `PCRBank` enum in responses.
 */
export type PCRBankName = `PCR_BANK_${PCRBank}`;

/**
 * Proto name of each PCR bank. The REST decoder is protojson, which discards
 * the short name; requests send the value from this map.
 */
export const PCR_BANK_PROTO_NAMES: Readonly<Record<PCRBank, PCRBankName>> = {
  UNSPECIFIED: 'PCR_BANK_UNSPECIFIED',
  SHA1: 'PCR_BANK_SHA1',
  SHA256: 'PCR_BANK_SHA256',
  SHA384: 'PCR_BANK_SHA384',
  SHA512: 'PCR_BANK_SHA512',
  SM3_256: 'PCR_BANK_SM3_256',
};

// =============================================================================
// Data Types
// =============================================================================

/**
 * TPM manufacturer information
 */
export interface TPMManufacturer {
  /** Manufacturer name */
  name: string;
  /** Manufacturer ID */
  id: number;
  /** TPM model */
  model: string;
  /** Firmware version */
  firmwareVersion: string;
}

/**
 * TPM capability
 */
export interface TPMCapability {
  /** Capability name */
  name: string;
  /** Whether supported */
  supported: boolean;
  /** Capability value */
  value?: string;
}

/**
 * TPM capabilities: TPM2_GetCapability's algorithm, command and ECC-curve names
 */
export interface TPMCapabilitiesResponse {
  algorithms?: string[];
  commands?: string[];
  eccCurves?: string[];
}

/**
 * A provisioned key named by its persistent handle and algorithm
 */
export interface TPMKeyRef {
  handle?: number;
  algorithm?: string;
}

/**
 * TPM device and provisioned identity keys. A key that is not provisioned is absent.
 */
export interface TPMPlatformAttributesResponse {
  device?: string;
  isFips?: boolean;
  pcrExtended?: boolean;
  canSeal?: boolean;
  isSimulator?: boolean;
  manufacturer?: string;
  ek?: TPMKeyRef;
  srk?: TPMKeyRef;
  iak?: TPMKeyRef;
}

/**
 * Certify request: the IAK certifies the key at a persistent handle (TPM2_Certify)
 */
export interface CertifyRequest {
  keyHandle: number;
  /** The certified key's authValue; empty when it has none */
  keyPassword?: string;
  /** Qualifying data (base64), at most 64 bytes */
  nonce?: string;
}

/**
 * Certify response (byte fields are base64)
 */
export interface CertifyResponse {
  certifyInfo?: string;
  signature?: string;
  signatureAlgorithm?: string;
  certifyInfoSignature?: string;
  attestingKeyPublic?: string;
  attestedKeyPublic?: string;
  attestingKeyPublicArea?: string;
  attestedKeyPublicArea?: string;
  nonce?: string;
}

/**
 * A defined NV index as reported by TPM info (proto NVIndex).
 */
export interface NVIndex {
  /** NV index handle */
  handle: number;
  /** ordinary | counter | extend | bits | pin_pass | pin_fail */
  type: string;
  /** Payload size in bytes */
  size: number;
  /** Reads require the index auth value */
  authRead: boolean;
  /** Writes require the index auth value */
  authWrite: boolean;
}

/**
 * One digest of a TCG event-log entry (proto EventDigest).
 */
export interface EventDigest {
  /** Hash algorithm identifier */
  algorithmId: string;
  /** Digest (hex) */
  digest: string;
}

/**
 * A parsed TCG event-log entry (proto EventLogEntry).
 */
export interface EventLogEntry {
  /** Ordinal within the log */
  eventNum: number;
  /** PCR the event extended */
  pcrIndex: number;
  /** TCG event type name */
  eventType: string;
  /** Number of digests */
  digestCount: number;
  /** Digests, one per bank */
  digests: EventDigest[];
  /** Event data size in bytes */
  eventSize: number;
  /** Event data rendered as a string, when printable */
  eventString: string;
}

/**
 * PCR value
 */
export interface PCRValue {
  /** PCR index (0-23) */
  index: number;
  /** PCR bank, by the proto name the server writes and reads (`PCR_BANK_SHA256`) */
  bank: PCRBankName;
  /** PCR value (base64) */
  value: string;
}

/**
 * Key attributes for TPM key operations
 */
export interface KeyAttributes {
  /** Common name */
  cn: string;
  /** Key algorithm */
  algorithm: KeyAlgorithm;
  /** Hash algorithm for key operations */
  hash?: string;
  /** TPM handle */
  handle?: number;
  /** Make key persistent */
  persistent?: boolean;
  /** Key password */
  password?: string;
  /** Additional metadata */
  metadata?: Record<string, string>;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * TPM provision request
 */
export interface TPMProvisionRequest {
  /** Owner hierarchy password */
  ownerPassword?: string;
  /** Endorsement hierarchy password */
  endorsementPassword?: string;
  /** Create EK */
  createEk?: boolean;
  /** Create SRK */
  createSrk?: boolean;
  /** Create AK */
  createAk?: boolean;
  /** EK attributes */
  ekAttributes?: KeyAttributes;
  /** SRK attributes */
  srkAttributes?: KeyAttributes;
  /** AK attributes */
  akAttributes?: KeyAttributes;
}

/**
 * TPM clear request
 */
export interface TPMClearRequest {
  /** Owner password */
  ownerPassword: string;
  /** Confirmation */
  confirm: boolean;
}

/**
 * Create EK request
 */
export interface CreateEKRequest {
  /** Key attributes */
  attributes?: KeyAttributes;
  /** Make persistent */
  persistent?: boolean;
}

/**
 * Get EK request
 */
export interface GetEKRequest {
  /** Key algorithm filter */
  algorithm?: KeyAlgorithm;
  /** Handle filter */
  handle?: number;
}

/**
 * Get EK certificate request
 */
export interface GetEKCertificateRequest {
  /** Key algorithm filter */
  algorithm?: KeyAlgorithm;
  /** Handle filter */
  handle?: number;
}

/**
 * Import EK certificate request
 */
export interface ImportEKCertificateRequest {
  /** Certificate data (base64) */
  certificate: string;
  /** Format (PEM or DER) */
  format: 'PEM' | 'DER';
  /** NVRAM index for storage */
  nvramIndex?: number;
}

/**
 * Delete EK request
 */
export interface DeleteEKRequest {
  /** Handle */
  handle: number;
  /** Algorithm */
  algorithm?: KeyAlgorithm;
  /** Password */
  password?: string;
}

/**
 * Create SRK request
 */
export interface CreateSRKRequest {
  /** Key attributes */
  attributes?: KeyAttributes;
  /** Make persistent */
  persistent?: boolean;
  /** Parent (EK) handle */
  parentHandle?: number;
  /** Parent password */
  parentPassword?: string;
}

/**
 * Get SRK request
 */
export interface GetSRKRequest {
  /** Algorithm filter */
  algorithm?: KeyAlgorithm;
  /** Handle filter */
  handle?: number;
}

/**
 * Delete SRK request
 */
export interface DeleteSRKRequest {
  /** Handle */
  handle: number;
  /** Algorithm */
  algorithm?: KeyAlgorithm;
  /** Password */
  password?: string;
}

/**
 * Create AK request
 */
export interface CreateAKRequest {
  /** Key attributes */
  attributes?: KeyAttributes;
  /** Make persistent */
  persistent?: boolean;
  /** Parent (SRK) handle */
  parentHandle?: number;
  /** Parent password */
  parentPassword?: string;
}

/**
 * Get AK request
 */
export interface GetAKRequest {
  /** Algorithm filter */
  algorithm?: KeyAlgorithm;
  /** Handle filter */
  handle?: number;
}

/**
 * Delete AK request
 */
export interface DeleteAKRequest {
  /** Handle */
  handle: number;
  /** Algorithm */
  algorithm?: KeyAlgorithm;
  /** Password */
  password?: string;
}

/**
 * Seal request
 */
export interface SealRequest {
  /** Data to seal (base64) */
  data: string;
  /** Common name for sealed object */
  cn: string;
  /** Parent (SRK) handle */
  parentHandle?: number;
  /** Parent password */
  parentPassword?: string;
  /** Sealed object password */
  password?: string;
  /** PCR indices to seal to */
  pcrIndices?: number[];
  /** PCR bank */
  pcrBank?: PCRBank;
  /** Overwrite existing */
  overwrite?: boolean;
}

/**
 * Unseal request
 */
export interface UnsealRequest {
  /** Common name of sealed object */
  cn: string;
  /** Parent (SRK) handle */
  parentHandle?: number;
  /** Parent password */
  parentPassword?: string;
  /** Sealed object password */
  password?: string;
  /** PCR indices */
  pcrIndices?: number[];
  /** PCR bank */
  pcrBank?: PCRBank;
}

/**
 * Quote request
 */
export interface QuoteRequest {
  /** AK handle */
  akHandle: number;
  /** AK password */
  akPassword?: string;
  /** PCR indices to include */
  pcrIndices: number[];
  /** PCR bank */
  pcrBank?: PCRBank;
  /** Nonce (base64) */
  nonce: string;
}

/**
 * Verify quote request
 */
export interface VerifyQuoteRequest {
  /** Quote data (base64) */
  quote: string;
  /** Signature (base64) */
  signature: string;
  /**
   * AK public key (base64). Optional: proto3 `bytes ak_public` has no
   * presence, and both the REST and gRPC servers verify against the
   * platform IAK when it is absent (tpm_grpc_service.go
   * resolveVerifyAKPublic).
   */
  akPublic?: string;
  /**
   * Signature scheme the quote declared (QuoteResponse.signatureAlgorithm,
   * e.g. "SHA256-RSAPSS"). The signature is checked under it; a request
   * without it does not verify.
   */
  signatureAlgorithm?: string;
  /** Nonce (base64) */
  nonce: string;
  /**
   * Channel binding the quote was bound to (base64), as returned with it.
   * The node quoted SHA-256(nonce || channelBinding), so a bound quote
   * verifies only when this is sent with the nonce.
   */
  channelBinding?: string;
  /** Expected PCR values */
  expectedPcrs?: PCRValue[];
}

/**
 * Get event log request
 */
export interface GetEventLogRequest {
  /** Output format */
  format?: 'json' | 'binary' | 'text';
}

/**
 * Get PCRs request
 */
export interface GetPCRsRequest {
  /** PCR indices */
  indices: number[];
  /** PCR bank */
  bank?: PCRBank;
}

/**
 * Define NVRAM request
 */
export interface DefineNVRAMRequest {
  /** NVRAM index */
  index: number;
  /** Size in bytes */
  size: number;
  /** Password */
  password?: string;
  /** NVRAM attributes */
  attributes?: string[];
  /** Owner-hierarchy auth needed to define the index (proto parent_password) */
  parentPassword?: string;
}

/**
 * Write NVRAM request
 */
export interface WriteNVRAMRequest {
  /** NVRAM index */
  index: number;
  /** Data to write (base64) */
  data: string;
  /** Password */
  password?: string;
  /** Offset */
  offset?: number;
}

/**
 * Read NVRAM request
 */
export interface ReadNVRAMRequest {
  /** NVRAM index */
  index: number;
  /** Password */
  password?: string;
  /** Offset */
  offset?: number;
  /** Size to read */
  size?: number;
}

/**
 * Undefine NVRAM request
 */
export interface UndefineNVRAMRequest {
  /** NVRAM index */
  index: number;
  /** Password */
  password?: string;
}

/**
 * Get random request
 */
export interface GetRandomRequest {
  /** Number of bytes */
  numBytes: number;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface TPMStatus {
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
 * TPM info response: the proto `TPMInfoResponse` served flat by
 * `GET /api/v1/tpm/info`. Every field is always present.
 *
 * There is no `available` flag. A TPM is available when the call succeeds;
 * the server answers an unsuccessful response when it has none.
 */
export interface TPMInfoResponse {
  /** TPM version */
  version: TPMVersion;
  /** Manufacturer info; null when the server could not identify it */
  manufacturer: TPMManufacturer | null;
  /** Capabilities */
  capabilities: TPMCapability[];
  /** Available PCR banks */
  pcrBanks: PCRBankName[];
  /** Max NVRAM size */
  maxNvramSize: number;
  /** Is simulator */
  isSimulator: boolean;
  /** FIPS mode enabled */
  fipsMode: boolean;
  /** Additional properties */
  properties: Record<string, string>;
  /** Defined NV indexes */
  nvIndexes: NVIndex[];
}

/**
 * TPM provision response
 */
export interface TPMProvisionResponse {
  /** Operation status */
  status: TPMStatus;
  /** EK public key (base64) */
  ekPublic?: string;
  /** SRK public key (base64) */
  srkPublic?: string;
  /** AK public key (base64) */
  akPublic?: string;
  /** EK certificate (base64) */
  ekCertificate?: string;
}

/**
 * TPM clear response
 */
export interface TPMClearResponse {
  /** Operation status */
  status: TPMStatus;
}

/**
 * Create EK response
 */
export interface CreateEKResponse {
  /** Operation status */
  status: TPMStatus;
  /** Public key (base64) */
  publicKey?: string;
  /** TPM handle */
  handle?: number;
}

/**
 * Get EK response
 */
export interface GetEKResponse {
  /** Public key (base64) */
  publicKey: string;
  /** TPM handle */
  handle: number;
  /** Algorithm */
  algorithm: KeyAlgorithm;
}

/**
 * Get EK certificate response
 */
export interface GetEKCertificateResponse {
  /** Certificate (base64) */
  certificate: string;
  /** Format */
  format: string;
}

/**
 * Import EK certificate response
 */
export interface ImportEKCertificateResponse {
  /** Operation status */
  status: TPMStatus;
}

/**
 * Delete EK response
 */
export interface DeleteEKResponse {
  /** Operation status */
  status: TPMStatus;
}

/**
 * Create SRK response
 */
export interface CreateSRKResponse {
  /** Operation status */
  status: TPMStatus;
  /** Public key (base64) */
  publicKey?: string;
  /** TPM handle */
  handle?: number;
}

/**
 * Get SRK response
 */
export interface GetSRKResponse {
  /** Public key (base64) */
  publicKey: string;
  /** TPM handle */
  handle: number;
  /** Algorithm */
  algorithm: KeyAlgorithm;
}

/**
 * Delete SRK response
 */
export interface DeleteSRKResponse {
  /** Operation status */
  status: TPMStatus;
}

/**
 * Create AK response
 */
export interface CreateAKResponse {
  /** Operation status */
  status: TPMStatus;
  /** Public key (base64) */
  publicKey?: string;
  /** TPM handle */
  handle?: number;
  /** Credential blob for activation (base64) */
  credentialBlob?: string;
}

/**
 * Get AK response
 */
export interface GetAKResponse {
  /** Public key (base64) */
  publicKey: string;
  /** TPM handle */
  handle: number;
  /** Algorithm */
  algorithm: KeyAlgorithm;
}

/**
 * Delete AK response
 */
export interface DeleteAKResponse {
  /** Operation status */
  status: TPMStatus;
}

/**
 * Seal response
 */
export interface SealResponse {
  /** Operation status */
  status: TPMStatus;
  /** Sealed data (base64) */
  sealedData?: string;
  /** Public key blob (base64) */
  publicKey?: string;
  /** Private key blob (base64) */
  privateKey?: string;
}

/**
 * Unseal response
 */
export interface UnsealResponse {
  /** Operation status */
  status: TPMStatus;
  /** Unsealed data (base64) */
  data?: string;
}

/**
 * Quote response
 */
export interface QuoteResponse {
  /** Operation status */
  status: TPMStatus;
  /** Quote data (base64) */
  quote?: string;
  /** Signature (base64) */
  signature?: string;
  /**
   * Signature scheme the quote is signed under, e.g. "SHA256-RSAPSS".
   * Send it back as VerifyQuoteRequest.signatureAlgorithm.
   */
  signatureAlgorithm?: string;
  /** PCR values */
  pcrValues?: PCRValue[];
  /** Event log (base64) */
  eventLog?: string;
  /**
   * TLS exporter binding of the connection the request arrived on (base64).
   * The quote's qualifying data is SHA-256(nonce || channelBinding); see
   * checkQuoteBinding.
   */
  channelBinding?: string;
}

/**
 * Verify quote response
 */
export interface VerifyQuoteResponse {
  /** Operation status */
  status: TPMStatus;
  /** Whether verified */
  verified: boolean;
  /** Verification message */
  message?: string;
  /** Actual PCR values */
  actualPcrs?: PCRValue[];
}

/**
 * Get event log response
 */
export interface GetEventLogResponse {
  /** Event log data (base64) */
  eventLog: string;
  /** Format */
  format: string;
  /** Event count */
  eventCount: number;
  /** Parsed entries (proto entries; absent until server-side parsing ships) */
  entries?: EventLogEntry[];
}

/**
 * Get PCRs response
 */
export interface GetPCRsResponse {
  /** PCR values */
  pcrValues: PCRValue[];
}

/**
 * Define NVRAM response
 */
export interface DefineNVRAMResponse {
  /** Operation status */
  status: TPMStatus;
}

/**
 * Write NVRAM response
 */
export interface WriteNVRAMResponse {
  /** Operation status */
  status: TPMStatus;
}

/**
 * Read NVRAM response
 */
export interface ReadNVRAMResponse {
  /** Data read (base64) */
  data: string;
}

/**
 * Undefine NVRAM response
 */
export interface UndefineNVRAMResponse {
  /** Operation status */
  status: TPMStatus;
}

/**
 * Get random response
 */
export interface GetRandomResponse {
  /** Random bytes (base64) */
  randomBytes: string;
}

/**
 * Extend PCR request (POST /pcrs/extend)
 */
export interface ExtendPCRRequest {
  /** PCR index */
  index: number;
  /** Hash algorithm of the bank to extend (for example "SHA256") */
  hashAlg?: string;
  /** Data to extend into the PCR (base64) */
  data: string;
}

/**
 * Extend PCR response
 */
export interface ExtendPCRResponse {
  /** Operation status */
  status?: unknown;
}

/**
 * Make credential request (POST /make-credential)
 */
export interface TPMMakeCredentialRequest {
  /** Name of the attestation key (base64) */
  akName: string;
  /** Secret to wrap (base64); the TPM picks one when empty */
  secret?: string;
  /** EK certificate (base64 DER) */
  ekCert?: string;
  /** IAK public area (base64) */
  iakPub?: string;
}

/**
 * Make credential response
 */
export interface TPMMakeCredentialResponse {
  /** Credential blob (base64) */
  credentialBlob: string;
  /** Encrypted secret (base64) */
  encryptedSecret: string;
  /** The wrapped secret (base64) */
  secret?: string;
}

/**
 * Activate credential request (POST /activate-credential)
 */
export interface TPMActivateCredentialRequest {
  /** Credential blob (base64) */
  credentialBlob: string;
  /** Encrypted secret (base64) */
  encryptedSecret: string;
}

/**
 * Activate credential response
 */
export interface TPMActivateCredentialResponse {
  /** The recovered secret (base64) */
  secret: string;
}
