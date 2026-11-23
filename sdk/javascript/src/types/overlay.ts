/**
 * Overlay Service Types
 *
 * Types for VXLAN and multi-host networking operations.
 * Based on pkg/api/grpc/proto/overlay.proto
 */

// =============================================================================
// Data Types
// =============================================================================

/**
 * VTEP (VXLAN Tunnel Endpoint) information
 */
export interface VTEPInfo {
  /** Node ID */
  nodeId: string;
  /** IP address */
  ip: string;
  /** Whether healthy */
  healthy: boolean;
  /** Last seen timestamp */
  lastSeen: string;
}

/**
 * VNI (Virtual Network Identifier) configuration
 */
export interface VNIConfig {
  /** VNI number */
  vni: number;
  /** VLAN ID */
  vlan?: number;
  /** Name */
  name?: string;
  /** Labels */
  labels?: Record<string, string>;
}

/**
 * VNI information
 */
export interface VNI {
  /** VNI ID */
  id: string;
  /** Configuration */
  config: VNIConfig;
  /** Creation timestamp */
  createdAt: string;
  /** MAC address count */
  macCount: number;
}

/**
 * Tunnel information
 */
export interface TunnelInfo {
  /** Local VTEP */
  localVtep: string;
  /** Remote VTEP */
  remoteVtep: string;
  /** VNI */
  vni: number;
  /** Tunnel state */
  state: string;
  /** Bytes transmitted */
  bytesTx: number;
  /** Bytes received */
  bytesRx: number;
}

/**
 * Remote MAC entry
 */
export interface RemoteMACEntry {
  /** MAC address */
  mac: string;
  /** VNI */
  vni: number;
  /** Remote VTEP */
  remoteVtep: string;
  /** Learned timestamp */
  learnedAt: string;
}

/**
 * Overlay status
 */
export interface OverlayStatus {
  /** Node ID */
  nodeId: string;
  /** VTEP IP */
  vtepIp: string;
  /** VTEP count */
  vtepCount: number;
  /** VNI count */
  vniCount: number;
  /** Tunnel count */
  tunnelCount: number;
  /** Remote MAC count */
  remoteMacCount: number;
  /** Whether healthy */
  healthy: boolean;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * List VTEPs request
 */
export interface ListVTEPsRequest {}

/**
 * Get VTEP request
 */
export interface GetVTEPRequest {
  /** Node ID */
  nodeId: string;
}

/**
 * Create VNI request
 */
export interface CreateVNIRequest {
  /** Configuration */
  config: VNIConfig;
}

/**
 * Delete VNI request
 */
export interface DeleteVNIRequest {
  /** VNI number */
  vni: number;
}

/**
 * List VNIs request
 */
export interface ListVNIsRequest {}

/**
 * List tunnels request
 */
export interface ListTunnelsRequest {
  /** VNI filter (0 for all) */
  vni?: number;
}

/**
 * Get tunnel stats request
 */
export interface GetTunnelStatsRequest {
  /** Remote VTEP */
  remoteVtep: string;
  /** VNI */
  vni: number;
}

/**
 * List remote MACs request
 */
export interface ListRemoteMACsRequest {
  /** VNI filter (0 for all) */
  vni?: number;
}

/**
 * Forget MAC request
 */
export interface ForgetMACRequest {
  /** MAC address */
  mac: string;
  /** VNI */
  vni: number;
}

/**
 * Get overlay status request
 */
export interface GetOverlayStatusRequest {}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface OverlayOperationStatus {
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
 * List VTEPs response
 */
export interface ListVTEPsResponse {
  /** VTEPs */
  vteps: VTEPInfo[];
}

/**
 * Get VTEP response
 */
export interface GetVTEPResponse {
  /** VTEP */
  vtep: VTEPInfo;
}

/**
 * Create VNI response
 */
export interface CreateVNIResponse {
  /** Operation status */
  status: OverlayOperationStatus;
  /** Created VNI */
  vni?: VNI;
}

/**
 * Delete VNI response
 */
export interface DeleteVNIResponse {
  /** Operation status */
  status: OverlayOperationStatus;
}

/**
 * List VNIs response
 */
export interface ListVNIsResponse {
  /** VNIs */
  vnis: VNI[];
}

/**
 * List tunnels response
 */
export interface ListTunnelsResponse {
  /** Tunnels */
  tunnels: TunnelInfo[];
}

/**
 * Get tunnel stats response
 */
export interface GetTunnelStatsResponse {
  /** Tunnel */
  tunnel: TunnelInfo;
}

/**
 * List remote MACs response
 */
export interface ListRemoteMACsResponse {
  /** MAC entries */
  macs: RemoteMACEntry[];
}

/**
 * Forget MAC response
 */
export interface ForgetMACResponse {
  /** Operation status */
  status: OverlayOperationStatus;
}

/**
 * Get overlay status response
 */
export interface GetOverlayStatusResponse {
  /** Overlay status */
  status: OverlayStatus;
}
