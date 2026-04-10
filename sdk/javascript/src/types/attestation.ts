/**
 * Attestation Service Types
 *
 * Types for attestation operations including manifest management and quote operations.
 * Based on pkg/api/grpc/proto/attestation.proto
 */

// =============================================================================
// Enums
// =============================================================================

/**
 * Hash algorithm for attestation operations
 */
export type AttestationHashAlgorithm =
  | 'UNSPECIFIED'
  | 'SHA1'
  | 'SHA256'
  | 'SHA384'
  | 'SHA512';

/**
 * Manifest verification status
 */
export type ManifestVerificationStatus =
  | 'UNSPECIFIED'
  | 'UNKNOWN'
  | 'PENDING'
  | 'VERIFIED'
  | 'FAILED';

// =============================================================================
// Configuration Types
// =============================================================================

/**
 * Manifest builder configuration
 */
export interface ManifestBuilderConfig {
  /** Host identifier */
  hostId: string;
  /** Hash algorithm for Merkle tree */
  hashAlgorithm?: AttestationHashAlgorithm;
  /** PCR indices to include */
  pcrIndices?: number[];
  /** Nonce size in bytes */
  nonceSize?: number;
  /** Manifest format version */
  version?: string;
  /** Include workload PCR (PCR 14) */
  includeWorkloadPcr?: boolean;
}

/**
 * Manifest verifier configuration
 */
export interface ManifestVerifierConfig {
  /** Maximum manifest age in seconds (0 = no limit) */
  maxManifestAge?: number;
  /** Require valid host attestation */
  requireHostAttestation?: boolean;
  /** Verify Merkle root */
  verifyMerkleRoot?: boolean;
  /** Hash algorithm for verification */
  hashAlgorithm?: AttestationHashAlgorithm;
  /** Platform CA certificate PEM (base64) */
  platformCaCertPem?: string;
  /** Additional trusted roots PEM (base64) */
  trustedRootsPem?: string[];
}

/**
 * Attestation quote configuration
 */
export interface AttestationQuoteConfig {
  /** AK handle */
  akHandle?: number;
  /** PCR indices to include */
  pcrIndices?: number[];
  /** Hash algorithm */
  hashAlgorithm?: AttestationHashAlgorithm;
}

// =============================================================================
// Data Types
// =============================================================================

/**
 * PCR value for attestation
 */
export interface AttestationPCRValue {
  /** PCR index (0-23) */
  index: number;
  /** PCR value (base64) */
  value: string;
  /** Hash algorithm */
  algorithm: AttestationHashAlgorithm;
}

/**
 * Host attestation from physical TPM
 */
export interface HostAttestation {
  /** Raw TPM quote (base64) */
  quoteData: string;
  /** AK signature (base64) */
  signature: string;
  /** Signature algorithm */
  signatureAlgorithm: string;
  /** PCR values */
  pcrs: AttestationPCRValue[];
  /** PCR digest (base64) */
  pcrDigest: string;
  /** Anti-replay nonce (base64) */
  nonce: string;
  /** Quote timestamp */
  timestamp: string;
  /** AK public key (base64) */
  akPublicKey: string;
  /** IDevID certificate (base64) */
  idevidCertificate?: string;
  /** Hash algorithm */
  hashAlgorithm: AttestationHashAlgorithm;
  /** TPM firmware version */
  firmwareVersion?: string;
}

/**
 * VM attestation from vTPM
 */
export interface VMAttestation {
  /** VM identifier */
  vmId: string;
  /** Host identifier */
  hostId: string;
  /** Raw TPM quote (base64) */
  quoteData: string;
  /** AIK/AK signature (base64) */
  signature: string;
  /** Signature algorithm */
  signatureAlgorithm: string;
  /** PCR values */
  pcrs: AttestationPCRValue[];
  /** PCR digest (base64) */
  pcrDigest: string;
  /** Anti-replay nonce (base64) */
  nonce: string;
  /** Quote timestamp */
  timestamp: string;
  /** AIK/AK public key (base64) */
  aikPublicKey: string;
  /** vTPM EK certificate (base64) */
  ekCertificate?: string;
  /** Workload PCR 14 value (base64) */
  workloadPcr?: string;
  /** Hash algorithm */
  hashAlgorithm: AttestationHashAlgorithm;
  /** VM-specific metadata */
  metadata?: Record<string, string>;
}

/**
 * Container attestation
 */
export interface ContainerAttestation {
  /** Container identifier */
  containerId: string;
  /** Container image ID */
  imageId: string;
  /** Container image digest */
  imageDigest: string;
  /** Measurement hash (base64) */
  digest: string;
  /** PCR 14 value after extension (base64) */
  pcrValue: string;
  /** Measurement timestamp */
  timestamp: string;
  /** Container-specific metadata */
  metadata?: Record<string, string>;
}

/**
 * Host manifest for comprehensive attestation
 */
export interface HostManifest {
  /** Manifest identifier */
  id: string;
  /** Host identifier */
  hostId: string;
  /** Generation timestamp */
  timestamp: string;
  /** Anti-replay nonce (base64) */
  nonce: string;
  /** Host TPM attestation */
  host?: HostAttestation;
  /** VM attestations */
  vms: VMAttestation[];
  /** Container attestations */
  containers: ContainerAttestation[];
  /** Merkle root (base64) */
  merkleRoot: string;
  /** Manifest signature (base64) */
  signature: string;
  /** Signature algorithm */
  signatureAlgorithm: string;
  /** Manifest format version */
  version: string;
  /** Additional metadata */
  metadata?: Record<string, string>;
}

/**
 * Manifest verification result
 */
export interface ManifestVerificationResult {
  /** Overall verification status */
  status: ManifestVerificationStatus;
  /** Signature validity */
  signatureValid: boolean;
  /** Merkle root validity */
  merkleRootValid: boolean;
  /** Nonce validity */
  nonceValid: boolean;
  /** Timestamp validity */
  timestampValid: boolean;
  /** Host attestation validity */
  hostAttestationValid: boolean;
  /** All VM attestations valid */
  vmAttestationsValid: boolean;
  /** All container attestations valid */
  containerAttestationsValid: boolean;
  /** Verification timestamp */
  verifiedAt: string;
  /** Verification errors */
  errors: string[];
  /** VM-specific errors */
  vmErrors?: Record<string, string>;
  /** Container-specific errors */
  containerErrors?: Record<string, string>;
}

/**
 * Attestation quote
 */
export interface AttestationQuote {
  /** Raw TPM quote (base64) */
  quoteData: string;
  /** AK signature (base64) */
  signature: string;
  /** PCR values */
  pcrValues: AttestationPCRValue[];
  /** Nonce (base64) */
  nonce: string;
  /** Event log (base64) */
  eventLog?: string;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Get manifest request
 */
export interface GetManifestRequest {
  /** Manifest identifier */
  id: string;
}

/**
 * Build manifest request
 */
export interface BuildManifestRequest {
  /** Builder configuration */
  config: ManifestBuilderConfig;
  /** External nonce (base64, optional) */
  nonce?: string;
  /** Include VM attestations */
  includeVms?: boolean;
  /** Include container attestations */
  includeContainers?: boolean;
  /** Specific VM IDs to include */
  vmIds?: string[];
  /** Specific container IDs to include */
  containerIds?: string[];
  /** Sign the manifest */
  sign?: boolean;
}

/**
 * Verify manifest request
 */
export interface VerifyManifestRequest {
  /** Manifest to verify */
  manifest: HostManifest;
  /** Verifier configuration */
  config?: ManifestVerifierConfig;
  /** Expected nonce (base64) */
  expectedNonce?: string;
  /** Public key for signature verification (PEM, base64) */
  publicKeyPem?: string;
  /** Expected PCR values (index -> value base64) */
  expectedPcrs?: Record<number, string>;
}

/**
 * List manifests request
 */
export interface ListManifestsRequest {
  /** Filter by host ID */
  hostId?: string;
  /** Filter by start time (ISO 8601) */
  startTime?: string;
  /** Filter by end time (ISO 8601) */
  endTime?: string;
  /** Maximum results */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
}

/**
 * Delete manifest request
 */
export interface DeleteManifestRequest {
  /** Manifest identifier */
  id: string;
}

/**
 * Get attestation quote request
 */
export interface GetAttestationQuoteRequest {
  /** Quote configuration */
  config: AttestationQuoteConfig;
  /** Anti-replay nonce (base64) */
  nonce: string;
}

/**
 * Verify attestation quote request
 */
export interface VerifyAttestationQuoteRequest {
  /** Quote to verify */
  quote: AttestationQuote;
  /** AK public key (PEM, base64) */
  akPublicKeyPem: string;
  /** Expected nonce (base64) */
  expectedNonce: string;
  /** Expected PCR values */
  expectedPcrs?: AttestationPCRValue[];
}

/**
 * Collect host attestation request
 */
export interface CollectHostAttestationRequest {
  /** Quote configuration */
  config: AttestationQuoteConfig;
  /** Anti-replay nonce (base64) */
  nonce: string;
}

/**
 * Collect VM attestation request
 */
export interface CollectVMAttestationRequest {
  /** VM identifier */
  vmId: string;
  /** Quote configuration */
  config: AttestationQuoteConfig;
  /** Anti-replay nonce (base64) */
  nonce: string;
}

/**
 * Collect container attestation request
 */
export interface CollectContainerAttestationRequest {
  /** Container identifier */
  containerId: string;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface AttestationStatus {
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
 * Get manifest response
 */
export interface GetManifestResponse {
  /** Retrieved manifest */
  manifest: HostManifest;
}

/**
 * Build manifest response
 */
export interface BuildManifestResponse {
  /** Operation status */
  status: AttestationStatus;
  /** Built manifest */
  manifest?: HostManifest;
}

/**
 * Verify manifest response
 */
export interface VerifyManifestResponse {
  /** Operation status */
  status: AttestationStatus;
  /** Verification result */
  result?: ManifestVerificationResult;
}

/**
 * List manifests response
 */
export interface ListManifestsResponse {
  /** Manifests */
  manifests: HostManifest[];
  /** Total count */
  total: number;
}

/**
 * Delete manifest response
 */
export interface DeleteManifestResponse {
  /** Operation status */
  status: AttestationStatus;
}

/**
 * Get attestation quote response
 */
export interface GetAttestationQuoteResponse {
  /** Operation status */
  status: AttestationStatus;
  /** Generated quote */
  quote?: AttestationQuote;
}

/**
 * Verify attestation quote response
 */
export interface VerifyAttestationQuoteResponse {
  /** Operation status */
  status: AttestationStatus;
  /** Whether the quote is valid */
  verified: boolean;
  /** Verification message */
  message?: string;
  /** Actual PCR values from quote */
  actualPcrs?: AttestationPCRValue[];
}

/**
 * Collect host attestation response
 */
export interface CollectHostAttestationResponse {
  /** Operation status */
  status: AttestationStatus;
  /** Collected attestation */
  attestation?: HostAttestation;
}

/**
 * Collect VM attestation response
 */
export interface CollectVMAttestationResponse {
  /** Operation status */
  status: AttestationStatus;
  /** Collected attestation */
  attestation?: VMAttestation;
}

/**
 * Collect container attestation response
 */
export interface CollectContainerAttestationResponse {
  /** Operation status */
  status: AttestationStatus;
  /** Collected attestation */
  attestation?: ContainerAttestation;
}
