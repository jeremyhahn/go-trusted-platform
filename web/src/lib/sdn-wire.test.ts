import { describe, expect, it } from 'vitest';
import type { Bridge, BridgeStatus, BridgeType, FlowTable } from 'trusted-platform-sdk';
import {
  bridgeKind,
  bridgeKindLabels,
  flowActionKind,
  flowTableNumber,
  portState,
  readBridge,
  readUint64,
} from './sdn-wire';

// A bridge as the webservice answers it in a ListBridgesResponse (protojson).
function wireBridge(type: string, status: string): Bridge {
  return {
    id: 'br-int',
    config: { name: 'br-int', type: type as BridgeType },
    status: status as BridgeStatus,
    createdAt: '2026-10-26T00:00:00Z',
    updatedAt: '2026-10-26T00:00:00Z',
  };
}

describe('readBridge', () => {
  it('reads an OVS bridge as OVS, not vlan', () => {
    const row = readBridge(wireBridge('BRIDGE_TYPE_OVS', 'BRIDGE_STATUS_UP'));
    expect(row).toEqual({
      id: 'br-int',
      name: 'br-int',
      kind: 'ovs',
      status: 'active',
      createdAt: '2026-10-26T00:00:00Z',
    });
    expect(bridgeKindLabels[row.kind]).toBe('OVS');
  });

  it('reads Linux and VXLAN bridges and a failed bridge', () => {
    expect(readBridge(wireBridge('BRIDGE_TYPE_LINUX', 'BRIDGE_STATUS_DOWN'))).toMatchObject({
      kind: 'linux',
      status: 'pending',
    });
    expect(readBridge(wireBridge('BRIDGE_TYPE_VXLAN', 'BRIDGE_STATUS_ERROR'))).toMatchObject({
      kind: 'vxlan',
      status: 'error',
    });
  });

  it('does not read the old flat REST type word as OVS', () => {
    const row = readBridge(wireBridge('ovs', 'up'));
    expect(row.kind).toBe('unspecified');
    expect(row.status).toBe('pending');
  });

  it('names a bridge without a config by its id', () => {
    const bridge = { id: 'br-x', status: 'BRIDGE_STATUS_UP' } as unknown as Bridge;
    expect(readBridge(bridge)).toMatchObject({ name: 'br-x', kind: 'unspecified', createdAt: '' });
    expect(bridgeKind(undefined)).toBe('unspecified');
  });
});

describe('readUint64', () => {
  it('reads a protojson decimal string', () => {
    expect(readUint64('1073741824')).toBe(1073741824);
  });

  it('reads an absent or malformed counter as 0', () => {
    expect(readUint64(undefined)).toBe(0);
    expect(readUint64('')).toBe(0);
    expect(readUint64('not-a-number')).toBe(0);
    expect(readUint64('-5')).toBe(0);
  });
});

describe('flowTableNumber', () => {
  it('reads the table number from the enum name', () => {
    expect(flowTableNumber('FLOW_TABLE_0')).toBe(0);
    expect(flowTableNumber('FLOW_TABLE_3')).toBe(3);
    expect(flowTableNumber('FLOW_TABLE_DROP')).toBe(255);
  });

  it('reads an absent or unknown table as 0', () => {
    expect(flowTableNumber(undefined)).toBe(0);
    expect(flowTableNumber('TABLE_DROP' as FlowTable)).toBe(0);
  });
});

describe('flowActionKind', () => {
  it('maps each action enum to its OpenFlow word', () => {
    expect(flowActionKind('FLOW_ACTION_OUTPUT')).toBe('output');
    expect(flowActionKind('FLOW_ACTION_SET_VLAN')).toBe('mod_vlan_vid');
    expect(flowActionKind('FLOW_ACTION_CONTROLLER')).toBe('controller');
  });

  it('reads an absent or unknown action as unspecified', () => {
    expect(flowActionKind(undefined)).toBe('unspecified');
    expect(flowActionKind('OUTPUT' as never)).toBe('unspecified');
  });
});

describe('portState', () => {
  it('reads forwarding and blocked ports', () => {
    expect(portState('PORT_STATUS_UP')).toBe('up');
    expect(portState('PORT_STATUS_FORWARDING')).toBe('up');
    expect(portState('PORT_STATUS_BLOCKED')).toBe('blocked');
  });

  it('reads anything else as down', () => {
    expect(portState('PORT_STATUS_LEARNING')).toBe('down');
    expect(portState(undefined)).toBe('down');
    expect(portState('UP' as never)).toBe('down');
  });
});
