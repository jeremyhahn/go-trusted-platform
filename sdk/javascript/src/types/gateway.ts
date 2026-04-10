/**
 * Gateway Service Types
 *
 * Types for multi-mode gateway operations including BGP and IPAM.
 * Based on pkg/api/grpc/proto/gateway.proto
 */

// =============================================================================
// Enums
// =============================================================================

/**
 * Gateway mode
 */
export type GatewayMode =
  | 'UNSPECIFIED'
  | 'OVERLAY'
  | 'EDGE'
  | 'TRANSIT';

// =============================================================================
// Data Types
// =============================================================================

/**
 * Gateway status
 */
export interface GatewayStatus {
  /** Gateway ID */
  id: string;
  /** Node ID */
  nodeId: string;
  /** Active modes (bitmask) */
  modes: number;
  /** Tier (backbone, datacenter, coordinator) */
  tier?: string;
  /** Reputation score */
  reputation: number;
  /** Uptime in seconds */
  uptimeSeconds: number;
  /** Whether healthy */
  healthy: boolean;
  /** Start timestamp */
  startedAt: string;
}

/**
 * BGP peer information
 */
export interface BGPPeer {
  /** Peer address */
  address: string;
  /** Autonomous System Number */
  asn: number;
  /** Peer state */
  state: string;
  /** Description */
  description?: string;
  /** Prefixes received */
  prefixesReceived: number;
  /** Prefixes sent */
  prefixesSent: number;
  /** Uptime */
  uptime?: string;
}

/**
 * BGP status
 */
export interface BGPStatus {
  /** Local ASN */
  localAsn: number;
  /** Router ID */
  routerId: string;
  /** Peer count */
  peerCount: number;
  /** Established peers */
  establishedPeers: number;
  /** Prefixes announced */
  prefixesAnnounced: number;
  /** Whether running */
  running: boolean;
}

/**
 * Announced prefix
 */
export interface AnnouncedPrefix {
  /** Prefix (CIDR) */
  prefix: string;
  /** Next hop */
  nextHop: string;
  /** Announcement timestamp */
  announcedAt: string;
}

/**
 * IPAM pool
 */
export interface IPAMPool {
  /** Pool ID */
  id: string;
  /** CIDR */
  cidr: string;
  /** Gateway address */
  gateway?: string;
  /** Total addresses */
  total: number;
  /** Allocated addresses */
  allocated: number;
  /** Available addresses */
  available: number;
}

/**
 * IP allocation
 */
export interface IPAllocation {
  /** IP address */
  ip: string;
  /** Pool ID */
  poolId: string;
  /** Device ID */
  deviceId?: string;
  /** Hostname */
  hostname?: string;
  /** Allocation timestamp */
  allocatedAt: string;
  /** Expiration timestamp */
  expiresAt?: string;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Get gateway status request
 */
export interface GetGatewayStatusRequest {}

/**
 * Set gateway mode request
 */
export interface SetGatewayModeRequest {
  /** Modes (bitmask) */
  modes: number;
}

/**
 * Get BGP status request
 */
export interface GetBGPStatusRequest {}

/**
 * List BGP peers request
 */
export interface ListBGPPeersRequest {}

/**
 * Announce prefix request
 */
export interface AnnouncePrefixRequest {
  /** Prefix (CIDR) */
  prefix: string;
  /** Next hop */
  nextHop?: string;
}

/**
 * Withdraw prefix request
 */
export interface WithdrawPrefixRequest {
  /** Prefix (CIDR) */
  prefix: string;
}

/**
 * List announced prefixes request
 */
export interface ListAnnouncedPrefixesRequest {}

/**
 * List IPAM pools request
 */
export interface ListIPAMPoolsRequest {}

/**
 * Allocate IP request
 */
export interface AllocateIPRequest {
  /** Pool ID */
  poolId: string;
  /** Device ID */
  deviceId?: string;
  /** Hostname */
  hostname?: string;
}

/**
 * Release IP request
 */
export interface ReleaseIPRequest {
  /** IP address */
  ip: string;
}

/**
 * List allocations request
 */
export interface ListAllocationsRequest {
  /** Pool ID (empty for all) */
  poolId?: string;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface GatewayOperationStatus {
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
 * Get gateway status response
 */
export interface GetGatewayStatusResponse {
  /** Gateway status */
  status: GatewayStatus;
}

/**
 * Set gateway mode response
 */
export interface SetGatewayModeResponse {
  /** Operation status */
  status: GatewayOperationStatus;
  /** Updated gateway status */
  gatewayStatus?: GatewayStatus;
}

/**
 * Get BGP status response
 */
export interface GetBGPStatusResponse {
  /** BGP status */
  status: BGPStatus;
}

/**
 * List BGP peers response
 */
export interface ListBGPPeersResponse {
  /** BGP peers */
  peers: BGPPeer[];
}

/**
 * Announce prefix response
 */
export interface AnnouncePrefixResponse {
  /** Operation status */
  status: GatewayOperationStatus;
}

/**
 * Withdraw prefix response
 */
export interface WithdrawPrefixResponse {
  /** Operation status */
  status: GatewayOperationStatus;
}

/**
 * List announced prefixes response
 */
export interface ListAnnouncedPrefixesResponse {
  /** Announced prefixes */
  prefixes: AnnouncedPrefix[];
}

/**
 * List IPAM pools response
 */
export interface ListIPAMPoolsResponse {
  /** IPAM pools */
  pools: IPAMPool[];
}

/**
 * Allocate IP response
 */
export interface AllocateIPResponse {
  /** Operation status */
  status: GatewayOperationStatus;
  /** Allocation */
  allocation?: IPAllocation;
}

/**
 * Release IP response
 */
export interface ReleaseIPResponse {
  /** Operation status */
  status: GatewayOperationStatus;
}

/**
 * List allocations response
 */
export interface ListAllocationsResponse {
  /** Allocations */
  allocations: IPAllocation[];
}
