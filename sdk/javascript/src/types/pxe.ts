/**
 * PXE Service Types
 *
 * Types for PXE provisioning operations.
 * Based on pkg/api/grpc/proto/pxe.proto
 */

import type { DeviceProfile } from './device.js';

// =============================================================================
// Enums
// =============================================================================

/**
 * Provisioning state
 */
export type ProvisioningState =
  | 'UNSPECIFIED'
  | 'UNKNOWN'
  | 'DISCOVERED'
  | 'BOOTING'
  | 'INSTALLING'
  | 'INSTALL_COMPLETE'
  | 'ENROLLING'
  | 'ENROLLED'
  | 'AUTHORIZING'
  | 'AUTHORIZED'
  | 'FAILED'
  | 'QUARANTINED';

/**
 * Provisioning event type
 */
export type ProvisioningEventType =
  | 'UNSPECIFIED'
  | 'DEVICE_DISCOVERED'
  | 'PXE_BOOT_STARTED'
  | 'INSTALL_STARTED'
  | 'INSTALL_COMPLETED'
  | 'ENROLLMENT_STARTED'
  | 'ENROLLMENT_COMPLETED'
  | 'AUTHORIZATION_STARTED'
  | 'AUTHORIZATION_COMPLETED'
  | 'QUARANTINED'
  | 'FAILED'
  | 'RETRY';

// =============================================================================
// Data Types
// =============================================================================

/**
 * Provisioning event
 */
export interface ProvisioningEvent {
  /** Event ID */
  id: string;
  /** Device ID */
  deviceId: string;
  /** Timestamp */
  timestamp: string;
  /** Event type */
  eventType: ProvisioningEventType;
  /** State before event */
  fromState?: ProvisioningState;
  /** State after event */
  toState?: ProvisioningState;
  /** Event details */
  details?: Record<string, string>;
  /** Error message */
  error?: string;
}

/**
 * PXE device information
 */
export interface PXEDeviceInfo {
  /** Device ID */
  id: string;
  /** MAC address */
  macAddress: string;
  /** OVS port ID */
  portId?: string;
  /** Current state */
  state: ProvisioningState;
  /** State reason */
  stateReason?: string;
  /** Device profile */
  profile?: DeviceProfile;
  /** Certificate serial */
  certificateSerial?: string;
  /** Current VLAN */
  currentVlan?: number;
  /** Target VLAN */
  targetVlan?: number;
  /** Creation timestamp */
  createdAt: string;
  /** Update timestamp */
  updatedAt: string;
  /** State change timestamp */
  stateChangedAt?: string;
  /** Retry count */
  retryCount: number;
  /** Events */
  events?: ProvisioningEvent[];
}

/**
 * PXE device filter
 */
export interface PXEDeviceFilter {
  /** Filter by state */
  state?: ProvisioningState;
  /** Filter by MAC address */
  macAddress?: string;
  /** Filter by VLAN */
  vlan?: number;
  /** Limit */
  limit?: number;
  /** Offset */
  offset?: number;
}

/**
 * PXE service status
 */
export interface PXEServiceStatus {
  /** Whether running */
  running: boolean;
  /** Device count */
  deviceCount: number;
  /** Start time */
  startTime?: string;
  /** iPXE server address */
  ipxeServerAddr?: string;
  /** Quarantine VLAN */
  quarantineVlan?: number;
  /** Provisioning VLAN */
  provisioningVlan?: number;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Register device request
 */
export interface RegisterPXEDeviceRequest {
  /** MAC address */
  macAddress: string;
  /** Port ID */
  portId?: string;
}

/**
 * Get device request
 */
export interface GetPXEDeviceRequest {
  /** Device ID */
  deviceId: string;
}

/**
 * Get device by MAC request
 */
export interface GetPXEDeviceByMACRequest {
  /** MAC address */
  macAddress: string;
}

/**
 * List devices request
 */
export interface ListPXEDevicesRequest {
  /** Filter */
  filter?: PXEDeviceFilter;
}

/**
 * Remove device request
 */
export interface RemovePXEDeviceRequest {
  /** Device ID */
  deviceId: string;
}

/**
 * Update state request
 */
export interface UpdatePXEStateRequest {
  /** Device ID */
  deviceId: string;
  /** New state */
  state: ProvisioningState;
  /** Reason */
  reason?: string;
}

/**
 * Set device enrolled request
 */
export interface SetPXEDeviceEnrolledRequest {
  /** Device ID */
  deviceId: string;
  /** Certificate serial */
  certificateSerial: string;
}

/**
 * Authorize device request
 */
export interface AuthorizePXEDeviceRequest {
  /** Device ID */
  deviceId: string;
  /** Target VLAN */
  targetVlan?: number;
}

/**
 * Quarantine device request
 */
export interface QuarantinePXEDeviceRequest {
  /** Device ID */
  deviceId: string;
  /** Reason */
  reason?: string;
}

/**
 * Retry device request
 */
export interface RetryPXEDeviceRequest {
  /** Device ID */
  deviceId: string;
}

/**
 * Get events request
 */
export interface GetPXEEventsRequest {
  /** Device ID */
  deviceId: string;
}

/**
 * Get status request
 */
export interface GetPXEStatusRequest {}

/**
 * Start service request
 */
export interface StartPXEServiceRequest {}

/**
 * Stop service request
 */
export interface StopPXEServiceRequest {}

/**
 * Webhook complete request
 */
export interface PXEWebhookCompleteRequest {
  /** MAC address */
  macAddress: string;
  /** Hostname */
  hostname?: string;
  /** Success */
  success: boolean;
  /** Message */
  message?: string;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface PXEStatus {
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
 * Register device response
 */
export interface RegisterPXEDeviceResponse {
  /** Operation status */
  status: PXEStatus;
  /** Registered device */
  device?: PXEDeviceInfo;
}

/**
 * Get device response
 */
export interface GetPXEDeviceResponse {
  /** Device */
  device: PXEDeviceInfo;
}

/**
 * Get device by MAC response
 */
export interface GetPXEDeviceByMACResponse {
  /** Device */
  device: PXEDeviceInfo;
}

/**
 * List devices response
 */
export interface ListPXEDevicesResponse {
  /** Devices */
  devices: PXEDeviceInfo[];
  /** Total count */
  totalCount: number;
}

/**
 * Remove device response
 */
export interface RemovePXEDeviceResponse {
  /** Operation status */
  status: PXEStatus;
}

/**
 * Update state response
 */
export interface UpdatePXEStateResponse {
  /** Operation status */
  status: PXEStatus;
  /** Updated device */
  device?: PXEDeviceInfo;
}

/**
 * Set device enrolled response
 */
export interface SetPXEDeviceEnrolledResponse {
  /** Operation status */
  status: PXEStatus;
  /** Updated device */
  device?: PXEDeviceInfo;
}

/**
 * Authorize device response
 */
export interface AuthorizePXEDeviceResponse {
  /** Operation status */
  status: PXEStatus;
  /** Updated device */
  device?: PXEDeviceInfo;
}

/**
 * Quarantine device response
 */
export interface QuarantinePXEDeviceResponse {
  /** Operation status */
  status: PXEStatus;
  /** Updated device */
  device?: PXEDeviceInfo;
}

/**
 * Retry device response
 */
export interface RetryPXEDeviceResponse {
  /** Operation status */
  status: PXEStatus;
  /** Updated device */
  device?: PXEDeviceInfo;
}

/**
 * Get events response
 */
export interface GetPXEEventsResponse {
  /** Events */
  events: ProvisioningEvent[];
}

/**
 * Get status response
 */
export interface GetPXEStatusResponse {
  /** Service status */
  status: PXEServiceStatus;
}

/**
 * Start service response
 */
export interface StartPXEServiceResponse {
  /** Operation status */
  status: PXEStatus;
}

/**
 * Stop service response
 */
export interface StopPXEServiceResponse {
  /** Operation status */
  status: PXEStatus;
}

/**
 * Webhook complete response
 */
export interface PXEWebhookCompleteResponse {
  /** Operation status */
  status: PXEStatus;
}
