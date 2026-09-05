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
 * Device role
 */
export type DeviceRole =
  | 'UNSPECIFIED'
  | 'UNKNOWN'
  | 'SERVER'
  | 'CLIENT'
  | 'WORKSTATION'
  | 'EDGE'
  | 'IOT'
  | 'GATEWAY'
  | 'LOAD_BALANCER';

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
  attestPub?: string;
  /** EK certificate */
  ekCert?: string;
  /** Event log (base64) */
  eventLog?: string;
  /** Hash algorithm ID */
  hashAlgoId: number;
  /** Device model */
  model?: string;
  /** Serial number */
  serial: string;
  /** Signing public key */
  signingPub?: string;
  /** Creation timestamp */
  createdAt: string;
  /** Update timestamp */
  updatedAt: string;
}

/**
 * DHCP pool configuration
 */
export interface DHCPPoolConfig {
  /** Network CIDR */
  network: string;
  /** Range start IP */
  rangeStart: string;
  /** Range end IP */
  rangeEnd: string;
  /** Lease time in seconds */
  leaseTime: number;
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
  srcIp?: string;
  /** Destination IP */
  dstIp?: string;
  /** Source port */
  srcPort?: number;
  /** Destination port */
  dstPort?: number;
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
  dhcpPool?: DHCPPoolConfig;
  /** Static IP */
  staticIp?: string;
  /** Gateway IP */
  gateway?: string;
  /** DNS servers */
  dns?: string[];
  /** Authentication method */
  authMethod?: AuthMethod;
  /** ACLs */
  acls?: ACLConfig[];
  /** Subnet */
  subnet?: string;
  /** DNS server addresses */
  dnsServers?: string[];
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
  configType: string;
  /** Inline configuration (base64) */
  inline?: string;
  /** Configuration reference */
  reference?: string;
  /** Configuration name */
  configName?: string;
  /** Configuration path */
  configPath?: string;
  /** Configuration version */
  version?: string;
}

/**
 * Profile match rules
 */
export interface ProfileMatchRules {
  /** MAC address prefix */
  macPrefix?: string;
  /** Serial number prefix */
  serialPrefix?: string;
  /** Exact model match */
  model?: string;
  /** Model pattern (regex) */
  modelPattern?: string;
  /** Serial pattern (regex) */
  serialPattern?: string;
  /** Manufacturer match */
  manufacturerMatch?: string;
  /** TPM vendor */
  tpmVendor?: string;
  /** Custom attributes */
  customAttributes?: Record<string, string>;
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
  eventLog?: string;
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
  platformdConfig?: PlatformdConfigRef;
  /** Match rules */
  matchRules?: ProfileMatchRules;
  /** Full platform config (app.App as JSON) */
  config?: Record<string, unknown>;
  /** Endorsement key serial number */
  ekSerial?: string;
  /** MAC address */
  macAddress?: string;
  /** Whether the profile is assigned to a device */
  assigned?: boolean;
  /** Timestamp when the profile was assigned */
  assignedAt?: string;
  /** Creation timestamp */
  createdAt: string;
  /** Update timestamp */
  updatedAt: string;
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
  /** Device to create */
  device: Partial<Device>;
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
  tenantId: string;
  /** Template name */
  name: string;
  /** Template description */
  description: string;
  /** Device role */
  role: DeviceRole;
  /** Full platform config (app.App as JSON) */
  config?: Record<string, unknown>;
  /** Profile match rules */
  matchRules?: ProfileMatchRules;
  /** Creation timestamp */
  createdAt: string;
  /** Update timestamp */
  updatedAt: string;
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
  matchRules?: ProfileMatchRules;
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
  /** Profile match rules */
  matchRules?: ProfileMatchRules;
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
  /** Template ID (path parameter, not a body field) */
  templateId: number;
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
  /** Profile ID */
  profileId: number;
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
  /** Endorsement key serial number */
  ekSerial?: string;
  /** MAC address */
  macAddress?: string;
  /** Tenant ID */
  tenantId?: string;
  /** Assigned profile ID */
  profileId?: number;
  /** Whether the session has been fulfilled */
  fulfilled: boolean;
  /** Creation timestamp */
  createdAt: string;
  /** Expiration timestamp */
  expiresAt: string;
}

/**
 * Fulfill provisioning session request
 */
export interface FulfillSessionRequest {
  /** Session ID */
  sessionId: string;
  /** Profile ID to assign */
  profileId: number;
}
