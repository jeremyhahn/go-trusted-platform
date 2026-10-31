/**
 * Readers for the SDN REST routes' wire shape.
 *
 * The webservice answers every bridge, port, flow, policy and VLAN route with
 * its gRPC SDNService response message in the proto JSON mapping (#445,
 * docs/sdn/api-reference-rest.md): enums arrive as their names
 * (`BRIDGE_TYPE_OVS`) and uint64 counters as decimal strings.
 */
import type {
  Bridge,
  BridgeStatus,
  BridgeType,
  FlowActionType,
  FlowTable,
  PortStatus,
} from 'trusted-platform-sdk';

/** The kind of switch a bridge is, as the console shows it. */
export type SDNBridgeKind = 'ovs' | 'linux' | 'vxlan' | 'unspecified';

/** A bridge's state, as the console shows it. */
export type SDNBridgeState = 'active' | 'pending' | 'error';

/** One bridge as the console's tables show it. */
export interface SDNBridgeRow {
  id: string;
  name: string;
  kind: SDNBridgeKind;
  status: SDNBridgeState;
  createdAt: string;
}

/** A flow action as the console shows it (the OpenFlow action word). */
export type SDNFlowActionKind =
  | 'output'
  | 'drop'
  | 'mod_vlan_vid'
  | 'strip_vlan'
  | 'set_field'
  | 'goto_table'
  | 'controller'
  | 'unspecified';

/** A port's state, as the console shows it. */
export type SDNPortState = 'up' | 'down' | 'blocked';

/** The label the console shows for each bridge kind. */
export const bridgeKindLabels: Record<SDNBridgeKind, string> = {
  ovs: 'OVS',
  linux: 'Linux',
  vxlan: 'VXLAN',
  unspecified: 'Unspecified',
};

const bridgeKinds: Record<BridgeType, SDNBridgeKind> = {
  BRIDGE_TYPE_UNSPECIFIED: 'unspecified',
  BRIDGE_TYPE_OVS: 'ovs',
  BRIDGE_TYPE_LINUX: 'linux',
  BRIDGE_TYPE_VXLAN: 'vxlan',
};

const bridgeStates: Record<BridgeStatus, SDNBridgeState> = {
  BRIDGE_STATUS_UNSPECIFIED: 'pending',
  BRIDGE_STATUS_UP: 'active',
  BRIDGE_STATUS_DOWN: 'pending',
  BRIDGE_STATUS_ERROR: 'error',
};

// FLOW_TABLE_0 is enum value 1: the table number is in the name, not the value.
const flowTables: Record<FlowTable, number> = {
  FLOW_TABLE_UNSPECIFIED: 0,
  FLOW_TABLE_0: 0,
  FLOW_TABLE_1: 1,
  FLOW_TABLE_2: 2,
  FLOW_TABLE_3: 3,
  FLOW_TABLE_DROP: 255,
};

const flowActionKinds: Record<FlowActionType, SDNFlowActionKind> = {
  FLOW_ACTION_UNSPECIFIED: 'unspecified',
  FLOW_ACTION_OUTPUT: 'output',
  FLOW_ACTION_DROP: 'drop',
  FLOW_ACTION_SET_VLAN: 'mod_vlan_vid',
  FLOW_ACTION_STRIP_VLAN: 'strip_vlan',
  FLOW_ACTION_SET_FIELD: 'set_field',
  FLOW_ACTION_GOTO_TABLE: 'goto_table',
  FLOW_ACTION_CONTROLLER: 'controller',
};

const portStates: Record<PortStatus, SDNPortState> = {
  PORT_STATUS_UNSPECIFIED: 'down',
  PORT_STATUS_UP: 'up',
  PORT_STATUS_DOWN: 'down',
  PORT_STATUS_BLOCKED: 'blocked',
  PORT_STATUS_LEARNING: 'down',
  PORT_STATUS_FORWARDING: 'up',
};

/** Returns the kind of a bridge type; an absent or unknown type is `unspecified`. */
export function bridgeKind(type: BridgeType | undefined): SDNBridgeKind {
  if (type === undefined) return 'unspecified';
  return bridgeKinds[type] ?? 'unspecified';
}

/** Reads one bridge of a ListBridgesResponse into a console row. */
export function readBridge(bridge: Bridge): SDNBridgeRow {
  return {
    id: bridge.id,
    name: bridge.config?.name || bridge.id,
    kind: bridgeKind(bridge.config?.type),
    status: bridgeStates[bridge.status] ?? 'pending',
    createdAt: bridge.createdAt ?? '',
  };
}

/**
 * Reads a uint64 counter. protojson writes it as a decimal string; an absent
 * or malformed value reads as 0.
 */
export function readUint64(value: string | undefined): number {
  if (!value) return 0;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

/** Returns the OpenFlow table number a FlowTable names; unspecified is table 0. */
export function flowTableNumber(table: FlowTable | undefined): number {
  if (table === undefined) return 0;
  return flowTables[table] ?? 0;
}

/** Returns the OpenFlow action word of a flow action type. */
export function flowActionKind(type: FlowActionType | undefined): SDNFlowActionKind {
  if (type === undefined) return 'unspecified';
  return flowActionKinds[type] ?? 'unspecified';
}

/** Returns a port's state; anything not forwarding or blocked is down. */
export function portState(status: PortStatus | undefined): SDNPortState {
  if (status === undefined) return 'down';
  return portStates[status] ?? 'down';
}
