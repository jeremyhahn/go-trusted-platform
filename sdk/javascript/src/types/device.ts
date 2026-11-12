/**
 * Device Service Types
 *
 * Types for device and profile management operations.
 * Based on pkg/api/grpc/proto/device.proto
 */

// =============================================================================
// Enums
// =============================================================================

/**
 * Device role, as the REST API sends and accepts it: the ten lowercase
 * strings of `entities.DeviceRole` (`pkg/device/entities/profile.go`).
 * `unknown` is what the server reports for a profile or template saved
 * without a role. The server reads a role case-insensitively and also takes
 * `loadbalancer` for `load-balancer`, but it always writes one of these ten
 * and rejects anything else with a 400 (#119).
 */
export type DeviceRole =
  | 'unknown'
  | 'control-plane'
  | 'gateway'
  | 'worker'
  | 'server'
  | 'client'
  | 'workstation'
  | 'edge'
  | 'iot'
  | 'load-balancer';

/**
 * Authentication method
 */
export type AuthMethod =
  | 'UNSPECIFIED'
  | 'NONE'
  | '802_1X';

// =============================================================================
// Data Types
// =============================================================================

/**
 * Device information
 */
export interface Device {
  /** Device ID */
  id: string;
  /** Attestation public key */
  attest_pub?: string;
  /**
   * PEM-encoded attestation (IAK/AK) certificate the platform CA issued at
   * enrollment. It is the only trust anchor the quote verifier accepts: it
   * must chain to the platform CA and carry tcg-cap-verifiedTPMRestricted
   * (TCG DevID v1 r12 §8.2). A device without one is denied at attest time
   * with `ak_certificate_verified: false` (#374, #404).
   */
  attest_cert?: string;
  /** EK certificate */
  ek_cert?: string;
  /** Event log (base64) */
  event_log?: string;
  /** Hash algorithm ID */
  hash_algo_id: number;
  /** Device model */
  model?: string;
  /** Serial number */
  serial: string;
  /** Signing public key */
  signing_pub?: string;
  /** Creation timestamp */
  created_at: string;
  /** Update timestamp */
  updated_at: string;
  /** Lifecycle state (`registered`, `activated`, `attested`, `quarantined`, ...) */
  state?: string;
  /** When the device last heartbeated over mTLS (RFC 3339); drives the liveness badge */
  last_heartbeat_at?: string;
  /**
   * The mTLS peer address (host:port) the most recent heartbeat arrived from,
   * recorded from the connection and never from a body (#226). The collector
   * dials it when platform DNS has no record for the device. Read-only.
   */
  last_heartbeat_addr?: string;
}

/**
 * DHCP pool configuration
 */
export interface DHCPPoolConfig {
  /** Network CIDR */
  network: string;
  /** Range start IP */
  range_start: string;
  /** Range end IP */
  range_end: string;
  /** Lease time in seconds */
  lease_time: number;
}

/**
 * ACL configuration
 */
export interface ACLConfig {
  /** Priority */
  priority: number;
  /** Protocol */
  protocol: string;
  /** Source IP */
  src_ip?: string;
  /** Destination IP */
  dst_ip?: string;
  /** Source port */
  src_port?: number;
  /** Destination port */
  dst_port?: number;
  /** Action (allow, deny) */
  action: string;
}

/**
 * Network phase configuration
 */
export interface NetworkPhaseConfig {
  /** VLAN ID */
  vlan?: number;
  /** DHCP pool configuration */
  dhcp_pool?: DHCPPoolConfig;
  /** Static IP */
  static_ip?: string;
  /** Gateway IP */
  gateway?: string;
  /** DNS servers */
  dns?: string[];
  /** Authentication method */
  auth_method?: AuthMethod;
  /** ACLs */
  acls?: ACLConfig[];
  /** Subnet */
  subnet?: string;
  /** DNS server addresses */
  dns_servers?: string[];
  /** Enable DHCP */
  dhcp?: boolean;
  /** Firewall zone */
  firewallZone?: string;
}

/**
 * Platformd configuration reference
 */
export interface PlatformdConfigRef {
  /** Configuration type */
  config_type: string;
  /** Inline configuration (base64) */
  inline?: string;
  /** Configuration reference */
  reference?: string;
  /** Configuration name */
  config_name?: string;
  /** Configuration path */
  config_path?: string;
  /** Configuration version */
  version?: string;
}

/**
 * Profile match rules
 */
export interface ProfileMatchRules {
  /** MAC address prefix */
  mac_prefix?: string;
  /** Serial number prefix */
  serial_prefix?: string;
  /** Exact model match */
  model?: string;
  /** Model pattern (regex) */
  model_pattern?: string;
  /** Serial pattern (regex) */
  serial_pattern?: string;
  /** Manufacturer match */
  manufacturer_match?: string;
  /** TPM vendor */
  tpm_vendor?: string;
  /** Custom attributes */
  custom_attributes?: Record<string, string>;
}

/**
 * Device profile
 */
export interface DeviceProfile {
  /** Profile ID */
  id: string;
  /** Profile name */
  name: string;
  /** Device model */
  model?: string;
  /** Device role */
  role: DeviceRole;
  /** Event log (base64) */
  event_log?: string;
  /**
   * Named network phase configurations, keyed by logical phase name.
   *
   * The map is open-keyed: `provisioning`, `trusted` and `quarantine` are the
   * server's defaults, not the only keys it accepts. Which entry a device uses
   * at each point of its lifecycle is named by the three selector strings
   * below, never by the spelling of a key. Wire name `networks`
   * (`pkg/webservice/v1/device/types.go`, `ProfileFullResponse`).
   */
  networks?: Record<string, NetworkPhaseConfig>;
  /**
   * Key in `networks` used during enrollment. Omitted on the wire when the
   * server default {@link DEFAULT_ENROLLMENT_NETWORK} applies.
   */
  enrollment_network?: string;
  /**
   * Key in `networks` the device transitions to after successful enrollment.
   * Omitted on the wire when {@link DEFAULT_POST_ENROLLMENT_NETWORK} applies.
   */
  post_enrollment_network?: string;
  /**
   * Key in `networks` the device is moved to when enrollment or attestation
   * fails. Omitted on the wire when {@link DEFAULT_FAILURE_NETWORK} applies.
   */
  failure_network?: string;
  /** Platformd configuration */
  platformd_config?: PlatformdConfigRef;
  /** Match rules */
  match_rules?: ProfileMatchRules;
  /**
   * Expected measured state every device on this profile is verified
   * against (#373). Read-only: the verifier records it on the first fully
   * verified quote (`source: 'tofu'`) or a signed manifest supplies it
   * (`source: 'signed'`); the profile write routes ignore it.
   */
  pcr_baseline?: PCRBaseline;
  /**
   * Certificate name the attestation collector verifies a node of this
   * profile against when it dials it for a quote (#430). Omitted means the
   * device's own FQDN. Writable; an update that omits it keeps the stored
   * name.
   */
  tls_server_name?: string;
  /** Full platform config (app.App as JSON) */
  config?: Record<string, unknown>;
  /** Endorsement key serial number */
  ek_serial?: string;
  /** MAC address */
  mac_address?: string;
  /** Whether the profile is assigned to a device */
  assigned?: boolean;
  /** Timestamp when the profile was assigned */
  assigned_at?: string;
  /** Creation timestamp */
  created_at: string;
  /** Update timestamp */
  updated_at: string;
}

/** How a profile's PCR baseline was established. */
export type PCRBaselineSource = 'signed' | 'tofu';

/**
 * A profile's PCR baseline as the operator surface emits it
 * (`pkg/webservice/v1/device/types.go`, `PCRBaselineResponse`).
 */
export interface PCRBaseline {
  /** Expected digest per PCR, hex, keyed by the register index as a string */
  values: Record<string, string>;
  /** How the baseline was established */
  source: PCRBaselineSource;
  /** When the baseline was recorded (RFC 3339) */
  recorded_at: string;
  /** Device whose quote seeded a TOFU baseline; absent for a signed one */
  recorded_from_device_id?: string;
}

/**
 * The PCR indices a baseline covers, ascending. JSON object keys are
 * strings and arrive in no guaranteed order; a console that lists the
 * covered registers wants numbers in register order.
 */
export function pcrBaselineIndices(baseline: Pick<PCRBaseline, 'values'>): number[] {
  return Object.keys(baseline.values ?? {})
    .filter((key) => /^\d+$/.test(key))
    .map((key) => Number(key))
    .sort((a, b) => a - b);
}

/**
 * Server default for {@link DeviceProfile.enrollment_network}
 * (`pkg/device/entities/profile.go`, `DefaultEnrollmentNetwork`).
 */
export const DEFAULT_ENROLLMENT_NETWORK = 'provisioning';

/**
 * Server default for {@link DeviceProfile.post_enrollment_network}
 * (`pkg/device/entities/profile.go`, `DefaultPostEnrollmentNetwork`).
 */
export const DEFAULT_POST_ENROLLMENT_NETWORK = 'trusted';

/**
 * Server default for {@link DeviceProfile.failure_network}
 * (`pkg/device/entities/profile.go`, `DefaultFailureNetwork`).
 */
export const DEFAULT_FAILURE_NETWORK = 'quarantine';

/**
 * The three network phase selectors of a profile, resolved to the keys the
 * server will actually use.
 */
export interface NetworkPhaseSelectors {
  /** Key in `networks` used during enrollment */
  enrollment: string;
  /** Key in `networks` used after successful enrollment */
  postEnrollment: string;
  /** Key in `networks` used on enrollment or attestation failure */
  failure: string;
}

/**
 * Resolve a profile's network phase selectors.
 *
 * The server omits a selector from the wire when it is unset and applies its
 * default at use time, so a client that reads the raw fields sees `undefined`
 * where the device will in fact be placed on `provisioning`, `trusted` or
 * `quarantine`. This mirrors the entity's `Get*NetworkConfig` resolution.
 *
 * @param profile - Any object carrying the three selector fields
 * @returns The effective key for each phase; never empty
 */
export function networkPhaseSelectors(
  profile: Pick<DeviceProfile, 'enrollment_network' | 'post_enrollment_network' | 'failure_network'>
): NetworkPhaseSelectors {
  return {
    enrollment: selectorOrDefault(profile.enrollment_network, DEFAULT_ENROLLMENT_NETWORK),
    postEnrollment: selectorOrDefault(
      profile.post_enrollment_network,
      DEFAULT_POST_ENROLLMENT_NETWORK
    ),
    failure: selectorOrDefault(profile.failure_network, DEFAULT_FAILURE_NETWORK),
  };
}

/**
 * An unset selector is the Go zero value: the server omits it from the wire
 * (`omitempty`) or a client mirroring the struct sends `""`. Both mean "use
 * the default", so this deliberately treats the empty string as absent.
 */
function selectorOrDefault(value: string | undefined, fallback: string): string {
  return value === undefined || value === '' ? fallback : value;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Create device request
 */
export interface CreateDeviceRequest {
  /** Device to create. The serial is required; the server refuses an empty one. */
  device: Partial<Device> & Pick<Device, 'serial'>;
}

/**
 * Get device request
 */
export interface GetDeviceRequest {
  /** Device ID */
  id: string;
}

/**
 * Update device request
 */
export interface UpdateDeviceRequest {
  /** Device to update */
  device: Device;
}

/**
 * Delete device request
 */
export interface DeleteDeviceRequest {
  /** Device ID */
  id: string;
}

/**
 * Label selector for filtering
 */
export interface LabelSelector {
  /** Match labels */
  matchLabels?: Record<string, string>;
  /** Match expressions */
  matchExpressions?: Array<{
    key: string;
    operator: 'In' | 'NotIn' | 'Exists' | 'DoesNotExist';
    values?: string[];
  }>;
}

/**
 * List devices request
 */
export interface ListDevicesRequest {
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
  /** Label selector */
  selector?: LabelSelector;
}

/**
 * Find device by serial request
 */
export interface FindDeviceBySerialRequest {
  /** Serial number */
  serial: string;
}

/**
 * Create profile request
 */
export interface CreateProfileRequest {
  /** Profile to create */
  profile: Partial<DeviceProfile>;
}

/**
 * Get profile request
 */
export interface GetProfileRequest {
  /** Profile ID */
  id: string;
}

/**
 * Update profile request
 */
export interface UpdateProfileRequest {
  /** Profile to update */
  profile: DeviceProfile;
}

/**
 * Delete profile request
 */
export interface DeleteProfileRequest {
  /** Profile ID */
  id: string;
}

/**
 * List profiles request
 */
export interface ListProfilesRequest {
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
  /** Label selector */
  selector?: LabelSelector;
}

/**
 * Find profile by MAC address request
 */
export interface FindProfileByMACAddressRequest {
  /** MAC address */
  macAddress: string;
}

/**
 * Find profile by serial request
 */
export interface FindProfileBySerialRequest {
  /** Serial number */
  serial: string;
}

/**
 * Find matching profile request
 */
export interface FindMatchingProfileRequest {
  /** MAC address */
  macAddress?: string;
  /** Serial number */
  serial?: string;
  /** Model */
  model?: string;
}

/**
 * Attest device request: the device's quote evidence, base64 of the
 * JSON-encoded DeviceQuoteEvidence (docs/device/api.md §4.4).
 */
export interface DeviceAttestRequest {
  /** Base64 of `{quote, signature, nonce, pcrs}` */
  evidence: string;
}

/**
 * Disable device request (`POST /api/v1/devices/{id}/disable`,
 * docs/device/api.md). The device id travels in the path only.
 */
export interface DisableDeviceRequest {
  /** Why the device is disabled; recorded as `operator: <reason>` */
  reason?: string;
}

/**
 * Result of an operator disable or enable
 * (`pkg/webservice/v1/device/lifecycle_handler.go`, `DeviceLifecycleResponse`).
 */
export interface DeviceLifecycleResponse {
  /** Device ID, a decimal string so 64-bit IDs survive JSON */
  device_id: string;
  /** State after the transition: `suspended` on disable, `quarantined` on enable */
  state: string;
  /** State the device held before the transition */
  previous_state: string;
  /** Recorded reason, present when one was given */
  state_reason?: string;
  /** True when an enable queued an immediate re-attestation */
  reattestation_requested: boolean;
}

/**
 * Activate device request
 */
export interface ActivateDeviceRequest {
  /** Serial number */
  serial: string;
  /** MAC address */
  macAddress: string;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface DeviceStatus {
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
 * Pagination response
 */
export interface DevicePaginationResponse {
  /** Current page */
  page: number;
  /** Page size */
  pageSize: number;
  /** Total pages */
  totalPages: number;
  /** Total items */
  totalItems: number;
}

/**
 * Create device response
 */
export interface CreateDeviceResponse {
  /** Operation status */
  status: DeviceStatus;
  /** Created device */
  device?: Device;
}

/**
 * Get device response
 */
export interface GetDeviceResponse {
  /** Device */
  device: Device;
}

/**
 * Update device response
 */
export interface UpdateDeviceResponse {
  /** Operation status */
  status: DeviceStatus;
  /** Updated device */
  device?: Device;
}

/**
 * Delete device response
 */
export interface DeleteDeviceResponse {
  /** Operation status */
  status: DeviceStatus;
}

/**
 * List devices response
 */
export interface ListDevicesResponse {
  /** Devices */
  devices: Device[];
  /** Pagination info */
  pagination: DevicePaginationResponse;
}

/**
 * Find device by serial response
 */
export interface FindDeviceBySerialResponse {
  /** Found device */
  device?: Device;
}

/**
 * Count devices response
 */
export interface CountDevicesResponse {
  /** Device count */
  count: number;
}

/**
 * Create profile response
 */
export interface CreateProfileResponse {
  /** Operation status */
  status: DeviceStatus;
  /** Created profile */
  profile?: DeviceProfile;
}

/**
 * Get profile response
 */
export interface GetProfileResponse {
  /** Profile */
  profile: DeviceProfile;
}

/**
 * Update profile response
 */
export interface UpdateProfileResponse {
  /** Operation status */
  status: DeviceStatus;
  /** Updated profile */
  profile?: DeviceProfile;
}

/**
 * Delete profile response
 */
export interface DeleteProfileResponse {
  /** Operation status */
  status: DeviceStatus;
}

/**
 * List profiles response
 */
export interface ListProfilesResponse {
  /** Profiles */
  profiles: DeviceProfile[];
  /** Pagination info */
  pagination: DevicePaginationResponse;
}

/**
 * Find profile by MAC address response
 */
export interface FindProfileByMACAddressResponse {
  /** Found profile */
  profile?: DeviceProfile;
}

/**
 * Find profile by serial response
 */
export interface FindProfileBySerialResponse {
  /** Found profile */
  profile?: DeviceProfile;
}

/**
 * Find matching profile response
 */
export interface FindMatchingProfileResponse {
  /** Found profile */
  profile?: DeviceProfile;
}

/**
 * Count profiles response
 */
export interface CountProfilesResponse {
  /** Profile count */
  count: number;
}

/**
 * Attest device response (`pkg/webservice/v1/device/attest_handler.go`,
 * `AttestResponse`). Every check is reported separately so a console can
 * say which one failed. A failed verification is a 200 with
 * `verified: false`, not an error.
 */
export interface DeviceAttestResponse {
  /** Device ID */
  device_id: string;
  /** Serial number */
  serial?: string;
  /** Device model */
  model?: string;
  /** Overall verdict: every check below passed */
  verified: boolean;
  /** The certified key signed the quote */
  signature_valid: boolean;
  /** The quote's extraData is the caller's nonce */
  nonce_valid: boolean;
  /** Reported PCRs hash to the signed digest and equal the profile baseline */
  pcrs_valid: boolean;
  /** Lifecycle status after this verification */
  attestation_status: string;
  /** Human-readable reason, present on failure */
  message?: string;
  /** When the verification ran (RFC 3339) */
  attested_at: string;
  /**
   * The enrolled `attest_cert` chains to the platform CA and carries
   * tcg-cap-verifiedTPMRestricted (TCG DevID v1 r12 §8.2).
   */
  ak_certificate_verified: boolean;
  /** Which kind of baseline the quote was compared against; absent when none was evaluated */
  pcr_baseline_source?: PCRBaselineSource;
  /** When that baseline was recorded (RFC 3339) */
  pcr_baseline_recorded_at?: string;
  /** True when this call captured the profile's trust-on-first-use baseline */
  pcr_baseline_captured: boolean;
}

/**
 * Where a recorded attestation certificate came from: the certificate
 * already on the record, the platform CA's store, or a CA re-issuance.
 */
export type AttestCertSource = 'device' | 'ca' | 'reissued';

/**
 * Options for recording a device's attestation certificate
 * (`POST /api/v1/devices/{id}/attest-cert/record`, docs/device/api.md §4.5).
 *
 * There is deliberately no override: the server records a candidate only if
 * it chains to the platform CA, carries tcg-cap-verifiedTPMRestricted and
 * certifies the enrolled attestation key.
 */
export interface RecordAttestCertRequest {
  /**
   * When no existing candidate passes, ask the CA to issue a new certificate
   * over the enrolled attestation public key. Opt-in: a re-issued certificate
   * the server then refuses is revoked in the same call.
   */
  reissue?: boolean;
}

/** Response from recording a device's attestation certificate */
export interface RecordAttestCertResponse {
  /** Device ID */
  device_id: string;
  /** Serial number */
  serial?: string;
  /** Device model */
  model?: string;
  /** False when the record already held this exact certificate and nothing was written */
  changed: boolean;
  /** Which candidate was recorded */
  source: AttestCertSource;
  /** The CA store name it was found under, or the CN it was issued with */
  source_detail?: string;
  /** True when the CA was asked to issue a new certificate */
  reissued: boolean;
  /** Subject DN of the recorded certificate */
  subject: string;
  /** Serial number of the recorded certificate */
  certificate_serial: string;
  /** Expiry of the recorded certificate (RFC 3339) */
  not_after?: string;
  /** The recorded certificate, PEM encoded */
  attest_cert: string;
}

/**
 * Activate device response
 */
export interface ActivateDeviceResponse {
  /** Operation status */
  status: DeviceStatus;
  /** Activation status */
  activationStatus?: string;
  /** VLAN assigned */
  vlan?: number;
  /** Transition timestamp */
  transitionedAt?: string;
}

// =============================================================================
// Device Template Types
// =============================================================================

/**
 * Device template for standardized provisioning
 */
export interface DeviceTemplate {
  /** Template ID */
  id: string;
  /** Tenant ID */
  tenant_id: string;
  /** Template name */
  name: string;
  /** Template description */
  description: string;
  /** Device role */
  role: DeviceRole;
  /** Full platform config (app.App as JSON) */
  config?: Record<string, unknown>;
  /** Profile match rules */
  match_rules?: ProfileMatchRules;
  /** Creation timestamp */
  created_at: string;
  /** Update timestamp */
  updated_at: string;
}

/**
 * Create device template request
 */
export interface CreateDeviceTemplateRequest {
  /** Template name */
  name: string;
  /** Template description */
  description?: string;
  /** Device role */
  role: DeviceRole;
  /** Full platform config (app.App as JSON) */
  config?: Record<string, unknown>;
  /** Profile match rules */
  match_rules?: ProfileMatchRules;
}

/**
 * Update device template request
 */
export interface UpdateDeviceTemplateRequest {
  /** Template ID */
  id: string;
  /** Template name */
  name?: string;
  /** Template description */
  description?: string;
  /** Device role */
  role?: DeviceRole;
  /** Full platform config (app.App as JSON) */
  config?: Record<string, unknown>;
  /** Profile match rules (wire name `match_rules`) */
  match_rules?: ProfileMatchRules;
  /** Tenant ID; PUT replaces the stored template, so send it back unchanged */
  tenant_id?: string;
}

/**
 * List device templates request
 */
export interface ListDeviceTemplatesRequest {
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
}

/**
 * Create profile from template request
 */
export interface CreateProfileFromTemplateRequest {
  /**
   * Template ID (path parameter, not a body field). A string, like every id
   * the platform emits: ids are minted above 2^53, so a JavaScript number
   * cannot hold them (#342, #381); the route's `{id:[0-9]+}` accepts the
   * decimal string as-is.
   */
  templateId: string;
  /**
   * Profile field overrides. This is the ONLY body the server reads — its
   * `CreateProfileFromTemplateRequest` is `{template_id, overrides}` — so the
   * device's identity binding (EK serial, MAC address) belongs in here, not
   * beside it. Top-level `ekSerial` / `macAddress` fields used to live on this
   * type and were silently discarded by the server (#378).
   */
  overrides?: Partial<DeviceProfile>;
}

// =============================================================================
// Config Delivery Types
// =============================================================================

/**
 * Find config for device request
 */
export interface FindConfigForDeviceRequest {
  /** Endorsement key serial number */
  ekSerial?: string;
  /** MAC address */
  macAddress?: string;
}

/**
 * Assign profile to device request
 */
export interface AssignProfileToDeviceRequest {
  /** Profile ID, a decimal string: generated ids exceed 2^53 */
  profileId: string;
  /** Endorsement key serial number */
  ekSerial?: string;
  /** MAC address */
  macAddress?: string;
}

// =============================================================================
// Provisioning Session Types
// =============================================================================

/**
 * Provisioning session
 */
export interface ProvisioningSession {
  /** Session ID */
  id: string;
  /** Endorsement key serial number the device reported */
  ek_serial?: string;
  /** MAC address the device reported */
  mac_address?: string;
  /** Tenant ID */
  tenant_id?: string;
  /**
   * Linked profile ID, once fulfilled. A string: the server emits the
   * platform's wire id type, because ids are minted above 2^53 (#425).
   */
  profile_id?: string;
  /** The linked profile, once fulfilled */
  profile?: DeviceProfile;
  /** Whether the session has been fulfilled */
  fulfilled: boolean;
  /** Creation timestamp */
  created_at: string;
  /** Expiration timestamp */
  expires_at: string;
}

/**
 * Fulfill provisioning session request
 */
export interface FulfillSessionRequest {
  /**
   * Session ID. Wire name `session_id`: it travels in the path and, as the
   * server's `FulfillRequest` also carries it, in the body — the interface is
   * the body, field for field.
   */
  session_id: string;
  /**
   * Profile ID to link. Wire name `profile_id`
   * (`pkg/provisioning/configdelivery/types.go`, `FulfillRequest`); a string,
   * because ids are minted above 2^53 and the server accepts a string or a
   * number here since #418. This used to be `profileId: number`: the key was
   * never read, the server saw id 0, and the fulfil 404ed.
   */
  profile_id: string;
}
