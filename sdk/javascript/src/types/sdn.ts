/**
 * SDN (Software-Defined Networking) Service Types
 *
 * Types for SDN operations including bridges, ports, flows, and VLANs.
 * Based on pkg/api/grpc/proto/sdn.proto
 */

// =============================================================================
// Enums
// =============================================================================

/**
 * Bridge type
 */
export type BridgeType =
  | 'BRIDGE_TYPE_UNSPECIFIED'
  | 'BRIDGE_TYPE_OVS'
  | 'BRIDGE_TYPE_LINUX'
  | 'BRIDGE_TYPE_VXLAN';

/**
 * Port type
 */
export type PortType =
  | 'PORT_TYPE_UNSPECIFIED'
  | 'PORT_TYPE_INTERNAL'
  | 'PORT_TYPE_PHYSICAL'
  | 'PORT_TYPE_TAP'
  | 'PORT_TYPE_VETH'
  | 'PORT_TYPE_VXLAN'
  | 'PORT_TYPE_GRE';

/**
 * Bridge status
 */
export type BridgeStatus =
  | 'BRIDGE_STATUS_UNSPECIFIED'
  | 'BRIDGE_STATUS_UP'
  | 'BRIDGE_STATUS_DOWN'
  | 'BRIDGE_STATUS_ERROR';

/**
 * Port status
 */
export type PortStatus =
  | 'PORT_STATUS_UNSPECIFIED'
  | 'PORT_STATUS_UP'
  | 'PORT_STATUS_DOWN'
  | 'PORT_STATUS_BLOCKED'
  | 'PORT_STATUS_LEARNING'
  | 'PORT_STATUS_FORWARDING';

/**
 * Flow action type
 */
export type FlowActionType =
  | 'FLOW_ACTION_UNSPECIFIED'
  | 'FLOW_ACTION_OUTPUT'
  | 'FLOW_ACTION_DROP'
  | 'FLOW_ACTION_SET_VLAN'
  | 'FLOW_ACTION_STRIP_VLAN'
  | 'FLOW_ACTION_SET_FIELD'
  | 'FLOW_ACTION_GOTO_TABLE'
  | 'FLOW_ACTION_CONTROLLER';

/**
 * Flow table
 */
export type FlowTable =
  | 'FLOW_TABLE_UNSPECIFIED'
  | 'FLOW_TABLE_0'
  | 'FLOW_TABLE_1'
  | 'FLOW_TABLE_2'
  | 'FLOW_TABLE_3'
  | 'FLOW_TABLE_DROP';

/**
 * Flow priority
 */
export type FlowPriority =
  | 'UNSPECIFIED'
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL';

// =============================================================================
// Data Types
// =============================================================================

/**
 * Bridge configuration
 */
export interface BridgeConfig {
  /** Bridge name */
  name: string;
  /** Bridge type */
  type?: BridgeType;
  /** Datapath ID */
  datapathId?: string;
  /** STP enabled */
  stpEnabled?: boolean;
  /** MTU */
  mtu?: number;
  /** OpenFlow controllers */
  controllers?: string[];
  /** Additional options */
  options?: Record<string, string>;
  /** Labels */
  labels?: Record<string, string>;
}

/**
 * Bridge statistics
 */
export interface BridgeStats {
  /** Total ports (uint64: a decimal string in protojson) */
  totalPorts: string;
  /** Total flows */
  totalFlows: string;
  /** Packets received */
  packetsReceived: string;
  /** Packets sent */
  packetsSent: string;
  /** Bytes received */
  bytesReceived: string;
  /** Bytes sent */
  bytesSent: string;
  /** Errors */
  errors: string;
}

/**
 * Bridge information
 */
export interface Bridge {
  /** Bridge ID */
  id: string;
  /** Configuration */
  config: BridgeConfig;
  /** Status */
  status: BridgeStatus;
  /** Creation timestamp */
  createdAt: string;
  /** Update timestamp */
  updatedAt: string;
  /** Ports */
  ports?: Port[];
  /** Statistics */
  stats?: BridgeStats;
}

/**
 * Port configuration
 */
export interface PortConfig {
  /** Port name */
  name: string;
  /** Port type */
  type?: PortType;
  /** VLAN ID */
  vlan?: number;
  /** Trunk VLANs */
  trunkVlans?: number[];
  /** MAC address */
  macAddress?: string;
  /** MTU */
  mtu?: number;
  /** Promiscuous mode */
  promiscuous?: boolean;
  /** Additional options */
  options?: Record<string, string>;
  /** Labels */
  labels?: Record<string, string>;
}

/**
 * Port statistics
 */
export interface PortStats {
  /** Packets received (uint64: a decimal string in protojson) */
  packetsReceived: string;
  /** Packets sent */
  packetsSent: string;
  /** Bytes received */
  bytesReceived: string;
  /** Bytes sent */
  bytesSent: string;
  /** Errors */
  errors: string;
  /** Dropped */
  dropped: string;
}

/**
 * Port authentication
 */
export interface PortAuth {
  /** Whether authenticated */
  authenticated: boolean;
  /** Certificate CN */
  certificateCn?: string;
  /** Certificate (base64) */
  certificate?: string;
  /** Authentication timestamp */
  authenticatedAt?: string;
  /** Expiration timestamp */
  expiresAt?: string;
  /** Authorized VLANs */
  authorizedVlans?: number[];
}

/**
 * Port information
 */
export interface Port {
  /** Port ID */
  id: string;
  /** Bridge ID */
  bridgeId: string;
  /** Configuration */
  config: PortConfig;
  /** Status */
  status: PortStatus;
  /** Creation timestamp */
  createdAt: string;
  /** Update timestamp */
  updatedAt: string;
  /** Statistics */
  stats?: PortStats;
  /** Authentication */
  auth?: PortAuth;
}

/**
 * Flow match criteria
 */
export interface FlowMatch {
  /** Input port */
  inPort?: string;
  /** VLAN ID */
  vlanId?: number;
  /** Source MAC */
  ethSrc?: string;
  /** Destination MAC */
  ethDst?: string;
  /** Ethernet type */
  ethType?: number;
  /** Source IP */
  ipSrc?: string;
  /** Destination IP */
  ipDst?: string;
  /** IP protocol */
  ipProto?: number;
  /** TCP source port */
  tcpSrc?: number;
  /** TCP destination port */
  tcpDst?: number;
  /** UDP source port */
  udpSrc?: number;
  /** UDP destination port */
  udpDst?: number;
  /** Additional metadata */
  metadata?: Record<string, string>;
}

/**
 * Flow action
 */
export interface FlowAction {
  /** Action type */
  type: FlowActionType;
  /** Output port */
  port?: string;
  /** VLAN ID */
  vlanId?: number;
  /** Field name */
  field?: string;
  /** Field value */
  value?: string;
  /** Table ID */
  tableId?: number;
}

/**
 * Flow configuration
 */
export interface FlowConfig {
  /** Bridge ID */
  bridgeId: string;
  /** Flow table */
  table?: FlowTable;
  /** Priority */
  priority?: number;
  /** Match criteria */
  match?: FlowMatch;
  /** Actions */
  actions?: FlowAction[];
  /** Idle timeout */
  idleTimeout?: number;
  /** Hard timeout */
  hardTimeout?: number;
  /** Metadata */
  metadata?: Record<string, string>;
}

/**
 * Flow statistics
 */
export interface FlowStats {
  /** Packet count (uint64: a decimal string in protojson) */
  packetCount: string;
  /** Byte count (uint64: a decimal string in protojson) */
  byteCount: string;
  /** Duration in seconds */
  durationSeconds: number;
}

/**
 * Flow information
 */
export interface Flow {
  /** Flow ID */
  id: string;
  /** Configuration */
  config: FlowConfig;
  /** Creation timestamp */
  createdAt: string;
  /** Statistics */
  stats?: FlowStats;
}

/**
 * VLAN configuration
 */
export interface VLANConfig {
  /** VLAN ID */
  vlanId: number;
  /** VLAN name */
  name?: string;
  /** Bridge ID */
  bridgeId: string;
  /** Port IDs */
  ports?: string[];
  /** Labels */
  labels?: Record<string, string>;
}

/**
 * VLAN statistics
 */
export interface VLANStats {
  /** Port count */
  portCount: number;
  /** Packets (uint64: a decimal string in protojson) */
  packets: string;
  /** Bytes (uint64: a decimal string in protojson) */
  bytes: string;
}

/**
 * VLAN information
 */
export interface VLAN {
  /** VLAN ID (internal) */
  id: string;
  /** Configuration */
  config: VLANConfig;
  /** Creation timestamp */
  createdAt: string;
  /** Statistics */
  stats?: VLANStats;
}

/**
 * Flow log entry
 */
export interface FlowLogEntry {
  /** Timestamp */
  timestamp: string;
  /** Bridge ID */
  bridgeId: string;
  /** Flow ID */
  flowId: string;
  /** Action */
  action: string;
  /** Match criteria */
  match?: FlowMatch;
  /** Source IP */
  srcIp?: string;
  /** Destination IP */
  dstIp?: string;
  /** Source port */
  srcPort?: number;
  /** Destination port */
  dstPort?: number;
  /** Protocol */
  protocol?: string;
  /** Bytes */
  bytes?: number;
  /** Metadata */
  metadata?: Record<string, string>;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Create bridge request
 */
export interface CreateBridgeRequest {
  /** Bridge configuration */
  config: BridgeConfig;
}

/**
 * Delete bridge request
 */
export interface DeleteBridgeRequest {
  /** Bridge ID */
  id: string;
  /** Force delete */
  force?: boolean;
}

/**
 * Get bridge request
 */
export interface GetBridgeRequest {
  /** Bridge ID */
  id: string;
}

/**
 * Label selector for filtering
 */
export interface SDNLabelSelector {
  /** Match labels */
  matchLabels?: Record<string, string>;
}

/**
 * List bridges request
 */
export interface ListBridgesRequest {
  /** Label selector */
  selector?: SDNLabelSelector;
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
}

/**
 * Add port request
 */
export interface AddPortRequest {
  /** Bridge ID */
  bridgeId: string;
  /** Port configuration */
  config: PortConfig;
}

/**
 * Delete port request
 */
export interface DeletePortRequest {
  /** Bridge ID */
  bridgeId: string;
  /** Port ID */
  portId: string;
}

/**
 * Get port request
 */
export interface GetPortRequest {
  /** Bridge ID */
  bridgeId: string;
  /** Port ID */
  portId: string;
}

/**
 * List ports request
 */
export interface ListPortsRequest {
  /** Bridge ID */
  bridgeId: string;
  /** Label selector */
  selector?: SDNLabelSelector;
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
}

/**
 * Add flow request
 */
export interface AddFlowRequest {
  /** Flow configuration */
  config: FlowConfig;
}

/**
 * Delete flow request
 */
export interface DeleteFlowRequest {
  /** Bridge ID */
  bridgeId: string;
  /** Flow ID */
  flowId: string;
}

/**
 * List flows request
 */
export interface ListFlowsRequest {
  /** Bridge ID */
  bridgeId: string;
  /** Flow table */
  table?: FlowTable;
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
}

/**
 * Flush flows request
 */
export interface FlushFlowsRequest {
  /** Bridge ID */
  bridgeId: string;
  /** Flow table */
  table?: FlowTable;
}

/**
 * Create VLAN request
 */
export interface CreateVLANRequest {
  /** VLAN configuration */
  config: VLANConfig;
}

/**
 * Delete VLAN request
 */
export interface DeleteVLANRequest {
  /** Bridge ID */
  bridgeId: string;
  /** VLAN ID */
  vlanId: number;
}

/**
 * List VLANs request
 */
export interface ListVLANsRequest {
  /** Bridge ID */
  bridgeId: string;
  /** Label selector */
  selector?: SDNLabelSelector;
}

/**
 * Authenticate port request
 */
export interface AuthenticatePortRequest {
  /** Bridge ID */
  bridgeId: string;
  /** Port ID */
  portId: string;
  /** Certificate (base64) */
  certificate: string;
  /** Certificate format */
  format?: 'PEM' | 'DER';
}

/**
 * Revoke port auth request
 */
export interface RevokePortAuthRequest {
  /** Bridge ID */
  bridgeId: string;
  /** Port ID */
  portId: string;
}

/**
 * Get port stats request
 */
export interface GetPortStatsRequest {
  /** Bridge ID */
  bridgeId: string;
  /** Port ID */
  portId: string;
}

/**
 * Get flow stats request
 */
export interface GetFlowStatsRequest {
  /** Bridge ID */
  bridgeId: string;
  /** Flow ID */
  flowId: string;
}

/**
 * Stream flow logs request
 */
export interface StreamFlowLogsRequest {
  /** Bridge ID */
  bridgeId: string;
  /** Filter */
  filter?: FlowMatch;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface SDNStatus {
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
export interface SDNPaginationResponse {
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
 * Create bridge response
 */
export interface CreateBridgeResponse {
  /** Operation status */
  status: SDNStatus;
  /** Created bridge */
  bridge?: Bridge;
}

/**
 * Delete bridge response
 */
export interface DeleteBridgeResponse {
  /** Operation status */
  status: SDNStatus;
}

/**
 * Get bridge response
 */
export interface GetBridgeResponse {
  /** Bridge */
  bridge: Bridge;
}

/**
 * List bridges response
 */
export interface ListBridgesResponse {
  /** Bridges */
  bridges: Bridge[];
  /** Pagination info */
  pagination?: SDNPaginationResponse;
}

/**
 * Add port response
 */
export interface AddPortResponse {
  /** Operation status */
  status: SDNStatus;
  /** Added port */
  port?: Port;
}

/**
 * Delete port response
 */
export interface DeletePortResponse {
  /** Operation status */
  status: SDNStatus;
}

/**
 * Get port response
 */
export interface GetPortResponse {
  /** Port */
  port: Port;
}

/**
 * List ports response
 */
export interface ListPortsResponse {
  /** Ports */
  ports: Port[];
  /** Pagination info */
  pagination?: SDNPaginationResponse;
}

/**
 * Add flow response
 */
export interface AddFlowResponse {
  /** Operation status */
  status: SDNStatus;
  /** Added flow */
  flow?: Flow;
}

/**
 * Delete flow response
 */
export interface DeleteFlowResponse {
  /** Operation status */
  status: SDNStatus;
}

/**
 * List flows response
 */
export interface ListFlowsResponse {
  /** Flows */
  flows: Flow[];
  /** Pagination info */
  pagination?: SDNPaginationResponse;
}

/**
 * Flush flows response
 */
export interface FlushFlowsResponse {
  /** Operation status */
  status: SDNStatus;
  /** Deleted count */
  deletedCount: number;
}

/**
 * Create VLAN response
 */
export interface CreateVLANResponse {
  /** Operation status */
  status: SDNStatus;
  /** Created VLAN */
  vlan?: VLAN;
}

/**
 * Delete VLAN response
 */
export interface DeleteVLANResponse {
  /** Operation status */
  status: SDNStatus;
}

/**
 * List VLANs response
 */
export interface ListVLANsResponse {
  /** VLANs */
  vlans: VLAN[];
}

/**
 * Authenticate port response
 */
export interface AuthenticatePortResponse {
  /** Operation status */
  status: SDNStatus;
  /** Authentication info */
  auth?: PortAuth;
}

/**
 * Revoke port auth response
 */
export interface RevokePortAuthResponse {
  /** Operation status */
  status: SDNStatus;
}

/**
 * Get port stats response
 */
export interface GetPortStatsResponse {
  /** Statistics */
  stats: PortStats;
}

/**
 * Get flow stats response
 */
export interface GetFlowStatsResponse {
  /** Statistics */
  stats: FlowStats;
}
