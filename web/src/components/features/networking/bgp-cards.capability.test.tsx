import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { BGPPeersCard } from './bgp-peers-card';
import { BGPPrefixesCard } from './bgp-prefixes-card';

const { off } = vi.hoisted(() => ({ off: new Set<string>() }));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: 'not-configured: gateway' } : { enabled: true },
  }),
}));

// #2051: the BGP peers and announced-prefixes cards gate their controls on
// the server's capabilities.

const PEERS = 'GET /api/v1/gateway/bgp/peers';
const LIST = 'GET /api/v1/gateway/bgp/prefixes';
const ANNOUNCE = 'POST /api/v1/gateway/bgp/prefixes';
const WITHDRAW = 'DELETE /api/v1/gateway/bgp/prefixes';

function stub() {
  return stubControlPlane({
    [PEERS]: ok({ peers: [] }),
    [LIST]: ok({
      prefixes: [{ prefix: '198.51.100.0/24', nextHop: '192.0.2.1', announcedAt: '2026-11-21T10:00:00Z' }],
    }),
  });
}

async function renderPrefixes() {
  render(withControlPlane(<BGPPrefixesCard />));
  await waitFor(() => expect(screen.getAllByTestId('bgp-prefix-row')).toHaveLength(1));
}

describe('BGP cards capability gate', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    off.clear();
  });

  it("withholds Announce with the server's reason when POST /api/v1/gateway/bgp/prefixes is not offered", async () => {
    off.add(ANNOUNCE);
    stub();
    await renderPrefixes();
    fireEvent.change(screen.getByLabelText('Prefix'), { target: { value: '203.0.113.0/24' } });

    const announce = screen.getByRole('button', { name: 'Announce' }) as HTMLButtonElement;
    expect(announce.getAttribute('data-capability-op')).toBe(ANNOUNCE);
    expect(announce.getAttribute('data-capability-enabled')).toBe('false');
    expect(announce.disabled).toBe(true);
    expect(announce.getAttribute('title')).toBe('not-configured: gateway');
  });

  it('withholds Withdraw and its Confirm when DELETE /api/v1/gateway/bgp/prefixes is not offered', async () => {
    off.add(WITHDRAW);
    stub();
    await renderPrefixes();

    const withdraw = screen.getByRole('button', { name: 'Withdraw 198.51.100.0/24' }) as HTMLButtonElement;
    expect(withdraw.getAttribute('data-capability-op')).toBe(WITHDRAW);
    expect(withdraw.getAttribute('data-capability-enabled')).toBe('false');
    expect(withdraw.disabled).toBe(true);
    expect(withdraw.getAttribute('title')).toBe('not-configured: gateway');

    cleanup();
    off.clear();
    await renderPrefixes();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Withdraw 198.51.100.0/24' }));
    });
    const dialog = await screen.findByRole('dialog');
    const confirm = within(dialog).getByRole('button', { name: 'Confirm' });
    expect(confirm.getAttribute('data-capability-op')).toBe(WITHDRAW);
    expect(confirm.getAttribute('data-capability-enabled')).toBe('true');
  });

  it('withholds the peers Refresh when GET /api/v1/gateway/bgp/peers is not offered', async () => {
    off.add(PEERS);
    stub();
    render(withControlPlane(<BGPPeersCard />));
    await waitFor(() => expect(screen.getByText('No BGP peers')).toBeTruthy());

    const refresh = screen.getByRole('button', { name: 'Refresh' }) as HTMLButtonElement;
    expect(refresh.getAttribute('data-capability-op')).toBe(PEERS);
    expect(refresh.getAttribute('data-capability-enabled')).toBe('false');
    expect(refresh.disabled).toBe(true);
    expect(refresh.getAttribute('title')).toBe('not-configured: gateway');
  });
});
