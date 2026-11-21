import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { BGPPeersCard } from './bgp-peers-card';

// The card runs on the real SDK GatewayService through useBGPPrefixes; fetch is the only stub.
const PEERS = [
  { address: '192.0.2.1', asn: 65001, state: 'ESTABLISHED', prefixesReceived: 4, prefixesSent: 2, uptime: '3h' },
  { address: '192.0.2.2', asn: 65002, state: 'ACTIVE', prefixesReceived: 0, prefixesSent: 0 },
];

describe('BGPPeersCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('lists the peers and counts the ones down', async () => {
    stubControlPlane({ 'GET /api/v1/gateway/bgp/peers': ok({ peers: PEERS }) });
    render(withControlPlane(<BGPPeersCard />));

    await waitFor(() => expect(screen.getAllByTestId('bgp-peer-row')).toHaveLength(2));
    const [first, second] = screen.getAllByTestId('bgp-peer-row');
    for (const text of ['192.0.2.1', '65001', 'ESTABLISHED', '3h']) {
      expect(within(first).getByText(text)).toBeTruthy();
    }
    expect(within(second).getByText('ACTIVE')).toBeTruthy();
    expect(within(second).getByText('-')).toBeTruthy();
    expect(screen.getByTestId('bgp-peers-down').textContent).toBe('1 of 2 peers down');
  });

  it('shows an empty peer list', async () => {
    stubControlPlane({ 'GET /api/v1/gateway/bgp/peers': ok({ peers: [] }) });
    render(withControlPlane(<BGPPeersCard />));

    expect(await screen.findByText('No BGP peers')).toBeTruthy();
    expect(screen.getByTestId('bgp-peers-down').textContent).toBe('0 of 0 peers down');
  });

  it('re-reads the peers on Refresh', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/gateway/bgp/peers': ok({ peers: PEERS }) });
    render(withControlPlane(<BGPPeersCard />));

    await waitFor(() => expect(screen.getAllByTestId('bgp-peer-row')).toHaveLength(2));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    });
    await waitFor(() =>
      expect(sent.filter((s) => s.method === 'GET' && s.path === '/api/v1/gateway/bgp/peers')).toHaveLength(2)
    );
  });

  it('shows a refusal verbatim', async () => {
    stubControlPlane({ 'GET /api/v1/gateway/bgp/peers': refused(403, 'permission denied: sdn read') });
    render(withControlPlane(<BGPPeersCard />));

    const toast = await screen.findByText('BGP peers unavailable: permission denied: sdn read');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryAllByTestId('bgp-peer-row')).toHaveLength(0);
  });
});
