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
  /** Prefixes (CIDR) that are never allocatable; the gateway is always reserved */
  reserved?: string[];
  /** First address of the dynamic allocation window (whole CIDR when unset) */
  rangeStart?: string;
  /** Last address of the dynamic allocation window (whole CIDR when unset) */
  rangeEnd?: string;
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

// =============================================================================
// Telemetry snapshots (#594)
// =============================================================================

/**
 * One gateway's telemetry snapshot: what its services actually programmed,
 * as the control plane caches it.
 *
 * Field names are snake_case because this surface serialises the Go
 * `gwstate.Snapshot` struct directly rather than going through protojson's
 * camelCase mapping. A section a gateway does not run is **absent**, never
 * an empty object — so `undefined` means "not running", not "running and
 * empty".
 */
export interface GatewaySnapshot {
  gateway_id: string;
  hostname?: string;
  mode?: string;
  reported_at: string;
  received_at?: string;
  health?: GatewaySnapshotHealth;
  bgp?: GatewaySnapshotBGP;
  services?: GatewaySnapshotService[];
  tunnels?: GatewaySnapshotTunnel[];
  uplinks?: GatewaySnapshotUplink[];
  host_firewall?: GatewaySnapshotHostFirewall;
  firewall?: GatewaySnapshotFirewall;
  nat?: GatewaySnapshotNAT;
  pipeline?: GatewaySnapshotPipeline;
  pxe?: { status?: string; listen_address?: string; boots_served?: number; started_at?: string };
  dhcp?: { status?: string; lease_count?: number };
  annotations?: Record<string, string>;
}

/** Overall and per-component health. */
export interface GatewaySnapshotHealth {
  status?: string;
  components?: Record<string, string>;
  message?: string;
}

/** The BGP section: identity plus one entry per session. */
export interface GatewaySnapshotBGP {
  local_asn?: number;
  router_id?: string;
  peer_count: number;
  established_peers: number;
  announced_prefixes?: string[];
  received_prefixes: number;
  peers?: GatewaySnapshotBGPPeer[];
}

/** One BGP session as the speaker reports it. */
export interface GatewaySnapshotBGPPeer {
  address: string;
  asn?: number;
  description?: string;
  /** RFC 4271 FSM state: Idle, Connect, Active, OpenSent, OpenConfirm, Established. */
  state: string;
  uptime_seconds?: number;
  admin_down?: boolean;
  prefixes_received: number;
  /** What import policy admitted; the gap to prefixes_received is what was rejected. */
  prefixes_accepted: number;
  prefixes_sent: number;
  messages_received?: number;
  messages_sent?: number;
  local_address?: string;
  remote_router_id?: string;
  hold_time_seconds?: number;
  families?: string[];
  last_error?: string;
  bfd?: GatewaySnapshotBFD;
}

/** One neighbour's single-hop BFD session (RFC 5881). */
export interface GatewaySnapshotBFD {
  /** up, down, admin-down, init or unknown. */
  state: string;
  remote_state?: string;
  failure_transitions?: number;
  last_failure?: string;
  diagnostic?: string;
  remote_diagnostic?: string;
  tx_interval_ms?: number;
  rx_interval_ms?: number;
  detection_multiplier?: number;
}

/** One configured service section's disposition. */
export interface GatewaySnapshotService {
  name: string;
  active: boolean;
  healthy: boolean;
  /** The blocker behind a section the gateway refuses to run. */
  refused_reason?: string;
}

/** One managed tunnel. */
export interface GatewaySnapshotTunnel {
  name: string;
  transport?: string;
  type?: string;
  /** up, down or unknown. */
  state: string;
  uplink?: string;
  bound?: boolean;
  local_ip?: string;
  remote_ip?: string;
  tunnel_ip?: string;
  rx_bytes?: number;
  tx_bytes?: number;
  rx_packets?: number;
  tx_packets?: number;
  rekey_seconds?: number;
  last_rekey?: string;
}

/** One WAN uplink's policy-routing state. */
export interface GatewaySnapshotUplink {
  name: string;
  interface?: string;
  table: number;
  gateway_v4?: string;
  gateway_v6?: string;
  addresses?: string[];
  priority?: number;
  rule_count: number;
  tunnels?: string[];
}

/** The nftables host packet filter. */
export interface GatewaySnapshotHostFirewall {
  active: boolean;
  installed: boolean;
  fingerprint?: string;
  rule_count: number;
  last_reconcile?: string;
  last_error?: string;
}

/** The OVS conntrack firewall. */
export interface GatewaySnapshotFirewall {
  active: boolean;
  flow_count: number;
  last_reconcile?: string;
  ct_zones?: Record<string, number>;
}

/** The OVS NAT service, per-uplink pools included. */
export interface GatewaySnapshotNAT {
  active: boolean;
  snat_enabled: boolean;
  dnat_rules: number;
  ct_zone?: number;
  uplinks?: GatewaySnapshotNATUplink[];
}

/** One uplink's translation resources. */
export interface GatewaySnapshotNATUplink {
  name: string;
  default?: boolean;
  pool_addresses: number;
  ports: number;
  static: number;
}

/** The base OVS pipeline the gateway holds on its bridge. */
export interface GatewaySnapshotPipeline {
  installed: boolean;
  bridge?: string;
  owner?: string;
  terminal?: string;
  fail_mode?: string;
}

/**
 * Response of the control plane's fleet read: every gateway that has
 * reported, newest report first.
 */
export interface ListGatewayStateResponse {
  gateways: GatewaySnapshot[];
}

/**
 * NAT64 translator health (RFC 6146).
 *
 * Every field except the identity pair is what the kernel reported, not
 * what the configuration asked for: a started service whose instance has
 * gone reports `instance_present` false.
 */
export interface NAT64Status {
  /** Whether the service is started. */
  active: boolean;
  /** Whether the kernel held the instance at the last check. */
  instance_present: boolean;
  /** The RFC 6052 translation prefix in use. */
  prefix: string;
  /** The kernel instance name. */
  instance: string;
  /** Live translation session count. */
  sessions: number;
  /** Allocated address:port pairs. */
  pool4_used: number;
  /** The translator's reported version. */
  module_version?: string;
  /** Pipeline flows the service holds. */
  flow_count: number;
  /** When the translator and flows were last converged. */
  last_reconcile?: string;
  /** The last reconcile failure, absent when the last succeeded. */
  last_error?: string;
  /** When this snapshot was taken. */
  timestamp: string;
}

/** Response of the NAT64 status endpoint. */
export type GetNAT64StatusResponse = NAT64Status;
