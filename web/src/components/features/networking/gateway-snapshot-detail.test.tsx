import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import type { GatewaySnapshot } from 'trusted-platform-sdk';

import { GatewaySnapshotDetail } from './gateway-snapshot-detail';

// The datapath detail renders only the sections a gateway actually
// reports (#594): an absent section means "not running", and must not be
// drawn as an empty table an operator would read as "running, nothing
// configured".

function snapshot(overrides: Partial<GatewaySnapshot> = {}): GatewaySnapshot {
  return {
    gateway_id: 'lab-node-1-gateway',
    reported_at: '2026-09-08T22:00:00Z',
    health: { status: 'healthy' },
    services: [
      { name: 'tunnels', active: true, healthy: true },
      { name: 'dhcp', active: false, healthy: false, refused_reason: 'the DHCP service needs an IPAM allocator' },
    ],
    bgp: {
      local_asn: 401870,
      router_id: '23.143.36.4',
      peer_count: 2,
      established_peers: 1,
      received_prefixes: 118,
      peers: [
        {
          address: '10.255.0.2',
          asn: 401870,
          state: 'Established',
          prefixes_received: 120,
          prefixes_accepted: 118,
          prefixes_sent: 2,
          bfd: { state: 'up', remote_state: 'up', failure_transitions: 2 },
        },
        {
          address: '10.255.0.6',
          asn: 401870,
          state: 'Active',
          prefixes_received: 0,
          prefixes_accepted: 0,
          prefixes_sent: 0,
        },
      ],
    },
    tunnels: [
      {
        name: 'gre-mia',
        transport: 'ipsec',
        state: 'up',
        uplink: 'att',
        bound: true,
        local_ip: '99.12.246.36',
        remote_ip: '45.63.110.165',
        rx_bytes: 4096,
        tx_bytes: 2048,
        last_rekey: '2026-09-08T12:00:00Z',
      },
    ],
    uplinks: [
      { name: 'att', interface: 'eth6', table: 101, gateway_v4: '99.12.246.38', rule_count: 1, tunnels: ['gre-mia'] },
    ],
    host_firewall: { active: true, installed: true, fingerprint: 'sha256:abc', rule_count: 10 },
    firewall: { active: true, flow_count: 26 },
    nat: {
      active: true,
      snat_enabled: true,
      dnat_rules: 2,
      uplinks: [{ name: 'att', default: true, pool_addresses: 8, ports: 64512, static: 1 }],
    },
    pipeline: { installed: true, bridge: 'br-fabric', owner: 'lab-node-1-gateway', terminal: 'normal', fail_mode: 'secure' },
    ...overrides,
  };
}

describe('GatewaySnapshotDetail', () => {
  // The runner has no globals, so nothing unmounts a rendered tree for us.
  afterEach(cleanup);

  it('renders every section the gateway reports', () => {
    render(<GatewaySnapshotDetail snapshot={snapshot()} />);

    expect(screen.getByText('Datapath — lab-node-1-gateway')).toBeDefined();

    // Services, including the refusal reason for a section the gateway
    // cannot run.
    expect(screen.getByText('tunnels')).toBeDefined();
    expect(screen.getByText('the DHCP service needs an IPAM allocator')).toBeDefined();

    // BGP sessions with prefix counters and the BFD state.
    expect(screen.getByText(/AS 401870, router-id 23.143.36.4/)).toBeDefined();
    expect(screen.getByText('10.255.0.2')).toBeDefined();
    expect(screen.getByText('Established')).toBeDefined();
    expect(screen.getByText('118')).toBeDefined();
    expect(screen.getByText('up · 2 failures')).toBeDefined();
    expect(screen.getByText('not configured')).toBeDefined();

    // Tunnels, uplinks and the fixed sections.
    expect(screen.getAllByText('gre-mia').length).toBe(2);
    expect(screen.getByText('att (pinned)')).toBeDefined();
    expect(screen.getByText('4.0 KiB / 2.0 KiB')).toBeDefined();
    expect(screen.getByText('Uplink policy routes')).toBeDefined();
    expect(screen.getByText('Host filter (nftables)')).toBeDefined();
    expect(screen.getByText('sha256:abc')).toBeDefined();
    expect(screen.getByText('Firewall (OVS conntrack)')).toBeDefined();
    expect(screen.getByText('att (default)')).toBeDefined();
    expect(screen.getByText('Base pipeline')).toBeDefined();
    expect(screen.getByText('br-fabric')).toBeDefined();
  });

  it('omits the sections a gateway does not run', () => {
    render(
      <GatewaySnapshotDetail
        snapshot={{ gateway_id: 'bare', reported_at: '2026-09-08T22:00:00Z' }}
      />
    );

    expect(screen.getByText('Datapath — bare')).toBeDefined();
    expect(screen.queryByText('Tunnels')).toBeNull();
    expect(screen.queryByText('Uplink policy routes')).toBeNull();
    expect(screen.queryByText('Host filter (nftables)')).toBeNull();
    expect(screen.queryByText('Base pipeline')).toBeNull();
    expect(screen.queryByText('Services')).toBeNull();
  });

  it('reports a host filter that failed to apply', () => {
    render(
      <GatewaySnapshotDetail
        snapshot={snapshot({
          host_firewall: {
            active: true,
            installed: false,
            rule_count: 0,
            last_error: 'netlink: device busy',
          },
        })}
      />
    );

    expect(screen.getByText('Last error: netlink: device busy')).toBeDefined();
  });
});
