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

/** Proto name of an attestation hash algorithm. */
export type AttestationHashAlgorithmProtoName = `ATTESTATION_HASH_ALGORITHM_${AttestationHashAlgorithm}`;

/**
 * Proto name of each attestation hash algorithm. The REST decoder is
 * protojson, which discards the short name; requests send the value from
 * this map.
 */
export const ATTESTATION_HASH_ALGORITHM_PROTO_NAMES: Readonly<
  Record<AttestationHashAlgorithm, AttestationHashAlgorithmProtoName>
> = {
  UNSPECIFIED: 'ATTESTATION_HASH_ALGORITHM_UNSPECIFIED',
  SHA1: 'ATTESTATION_HASH_ALGORITHM_SHA1',
  SHA256: 'ATTESTATION_HASH_ALGORITHM_SHA256',
  SHA384: 'ATTESTATION_HASH_ALGORITHM_SHA384',
  SHA512: 'ATTESTATION_HASH_ALGORITHM_SHA512',
};

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
  /**
   * Scheme the AK signed under, as x509.SignatureAlgorithm names it
   * (e.g. "SHA256-RSAPSS", "ECDSA-SHA256"). Verification refuses a
   * quote that declares none or an unknown one.
   */
  signatureAlgorithm: string;
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
  /**
   * Channel binding the quote was bound to (base64), as returned with it.
   * The node quoted SHA-256(nonce || channelBinding), so a bound quote
   * verifies only when this is sent with the nonce.
   */
  channelBinding?: string;
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
  /**
   * TLS exporter binding of the connection the request arrived on (base64).
   * The quote's qualifying data is SHA-256(nonce || channelBinding); see
   * checkQuoteBinding.
   */
  channelBinding?: string;
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
/**
 * PCR value exactly as the REST attestation routes emit it.
 *
 * Distinct from AttestationPCRValue, which types `algorithm` as the
 * AttestationHashAlgorithm union. The server writes `pcr.Algorithm.String()`,
 * whose output is not pinned to those five literals anywhere this SDK can see,
 * so narrowing it here would reject a response the server considers valid.
 * Widen this to the union only after pinning the Go side's output.
 */
export interface AttestationPCRValueWire {
  /** PCR index (0-23) */
  index: number;
  /** PCR value (base64) */
  value: string;
  /** Hash algorithm, as the server stringifies it */
  algorithm: string;
}

export interface CollectVMAttestationResponse {
  /** VM identifier */
  vm_id: string;
  /** Host identifier */
  host_id: string;
  /** Whether the quote verified */
  verified: boolean;
  /** Raw TPM quote (base64) */
  quote_data: string;
  /** AIK/AK signature (base64) */
  signature: string;
  /** Signature algorithm */
  signature_algorithm: string;
  /** PCR values */
  pcrs: AttestationPCRValueWire[];
  /** PCR digest (base64) */
  pcr_digest: string;
  /** Anti-replay nonce (base64) */
  nonce: string;
  /** RFC 3339 timestamp */
  timestamp: string;
  /** AIK public key, PEM encoded */
  aik_public_key_pem?: string;
  /** Hash algorithm the quote used */
  hash_algorithm: string;
  /** Workload PCR, when the VM measured one */
  workload_pcr?: string;
  /** Free-form metadata */
  metadata?: Record<string, string>;
}

/**
 * Collect container attestation response
 */
export interface CollectContainerAttestationResponse {
  /** Container identifier */
  container_id: string;
  /** Image identifier */
  image_id?: string;
  /** Image digest */
  image_digest?: string;
  /** Whether the measurement verified */
  verified: boolean;
  /** Measured digest */
  digest: string;
  /** PCR the container measurement extended */
  pcr_value: string;
  /** RFC 3339 timestamp */
  timestamp: string;
  /** Free-form metadata */
  metadata?: Record<string, string>;
}

// =============================================================================
// Device reports — the collector's cached verdicts (#226, #428)
// =============================================================================

/** How the PCR baseline a report was compared against was established. */
export type DeviceReportBaselineSource = 'signed' | 'tofu';

/**
 * One device's attestation report as every transport renders it
 * (`pkg/attestation/reporting.View`; docs/attestation/api.md §5.3).
 *
 * A consumer that shows `verified` without `fresh` and `age_seconds` is
 * misrepresenting the report: the verdict is only as good as the evidence is
 * recent. A missing report (`404`) is "never collected" and is NOT a failed
 * verdict — a failed verdict is a report whose `verified` is false.
 */
export interface DeviceReport {
  /** Device ID (a JSON string; ids exceed 2^53) */
  device_id: string;
  /** Serial number */
  serial?: string;
  /** Device model */
  model?: string;
  /** Overall verdict: every check below passed */
  verified: boolean;
  /** The enrolled attestation certificate chains to the platform CA and carries verifiedTPMRestricted */
  ak_certificate_verified: boolean;
  /** The certified key signed the quote */
  signature_valid: boolean;
  /** The quote's extraData is the collector's nonce */
  nonce_valid: boolean;
  /** Reported PCRs hash to the signed digest and equal the profile baseline */
  pcrs_valid: boolean;
  /**
   * A negative verdict came from a check that ran and FAILED — the only kind
   * that quarantines. False on a negative verdict means a check could not run
   * (no certificate, no CA, no baseline): absence of evidence.
   */
  cryptographic_failure: boolean;
  /** Which kind of baseline the quote was compared against; absent when none was evaluated */
  pcr_baseline_source?: DeviceReportBaselineSource;
  /** When that baseline was recorded (RFC 3339) */
  pcr_baseline_recorded_at?: string;
  /** This collection captured the profile's trust-on-first-use baseline */
  pcr_baseline_captured: boolean;
  /** Lifecycle status after this verification */
  status: string;
  /** Human-readable reason, present on failure */
  message?: string;
  /** The verifier's timestamp (RFC 3339) */
  attested_at: string;
  /** The collector's timestamp (RFC 3339) */
  collected_at: string;
  /** The cache's freshness verdict at render time */
  fresh: boolean;
  /** Age of the evidence in seconds at `as_of` */
  age_seconds: number;
  /** The instant `fresh` and `age_seconds` were computed (RFC 3339) */
  as_of: string;
  /**
   * The DEVICE's own clock trust state at collection. Absent when the device
   * did not report it, which is not the same claim as `false`: a machine
   * whose clock could not be read is not a machine with a wrong clock. A
   * console must render the two differently (#509).
   */
  time_synced?: boolean;
}

/** `GET /api/v1/attestation/reports` — every cached report. */
export interface ListDeviceReportsResponse {
  reports: DeviceReport[];
  count: number;
}

/**
 * `POST /api/v1/attestation/reports/{device_id}/refresh` — 202. The
 * collector applies its own TTL and coalescing; read the report again for the
 * new verdict and its age. There is never a synchronous quote.
 */
export interface RefreshDeviceReportResponse {
  device_id: string;
  enqueued: boolean;
  note: string;
}

/**
 * `GET /api/v1/attestation/callers` — which machine callers this node admits
 * to its quote-producing routes (`calleradmission.Description`).
 */
export interface CallerPolicyDescription {
  strategy: string;
  identities: string[];
  identities_source?: string;
  list_valid: boolean;
  invalid_entries?: string[];
  anchors_configured: boolean;
  anchor_source?: string;
  attested_peers_available: boolean;
  /** True when the compiled policy admits no caller at all */
  admits_nobody: boolean;
}

/**
 * The four states a device report route can leave a console in. They must
 * render distinctly (docs/attestation/user.md): "never collected" is a 404
 * and is not a failed verdict; "not configured" is a 503 from a node without
 * the reporting service; anything else is a transport or authorization error.
 */
export type DeviceReportState =
  | { kind: 'report'; report: DeviceReport }
  | { kind: 'never-collected' }
  | { kind: 'not-configured' }
  | { kind: 'error'; status?: number | undefined; message: string };

/**
 * Classify a `getDeviceReport` response into the state a console renders.
 *
 * This is the response-shape gate the acceptance criteria ask for: the
 * branch is taken on what the server actually answers (HTTP status on the
 * error envelope, a report body on success), in one place, rather than in
 * each page.
 */
export function classifyDeviceReport(response: {
  success: boolean;
  data?: DeviceReport;
  error?: { status?: number; message: string };
}): DeviceReportState {
  if (response.success && response.data && typeof response.data.device_id === 'string') {
    return { kind: 'report', report: response.data };
  }
  const status = response.error?.status;
  if (status === 404) {
    return { kind: 'never-collected' };
  }
  if (status === 503) {
    return { kind: 'not-configured' };
  }
  return {
    kind: 'error',
    status,
    message: response.error?.message ?? 'attestation report unavailable',
  };
}
