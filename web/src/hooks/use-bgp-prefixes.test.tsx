import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { normalizePrefix, peersDown, useBGPPrefixes } from './use-bgp-prefixes';

// The hook runs on the real SDK GatewayService; fetch is the only stub.
const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

function renderBGP() {
  return renderHook(() => useBGPPrefixes(), { wrapper });
}

describe('useBGPPrefixes', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('lists the peers and picks the ones down', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/gateway/bgp/peers': ok({
        peers: [
          { address: '192.0.2.1', asn: 65001, state: 'ESTABLISHED', prefixesReceived: 3, prefixesSent: 1 },
          { address: '192.0.2.2', asn: 65002, state: 'ACTIVE', prefixesReceived: 0, prefixesSent: 0 },
        ],
      }),
    });
    const { result } = renderBGP();
    let res: Awaited<ReturnType<typeof result.current.listPeers>> | undefined;
    await act(async () => {
      res = await result.current.listPeers();
    });
    expect(res?.data?.peers).toHaveLength(2);
    expect(peersDown(res!.data!.peers).map((p) => p.address)).toEqual(['192.0.2.2']);
    expect(sent[0]).toMatchObject({ method: 'GET', path: '/api/v1/gateway/bgp/peers' });
  });

  it('announces a prefix with and without a next hop', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/gateway/bgp/prefixes': ok({ status: { success: true, message: 'announced' } }),
    });
    const { result } = renderBGP();
    let res: Awaited<ReturnType<typeof result.current.announce>> | undefined;
    await act(async () => {
      res = await result.current.announce(' 198.51.100.0/24 ', '192.0.2.1');
    });
    await act(async () => {
      res = await result.current.announce('2001:db8::/48');
    });
    expect(sent.map((s) => s.body)).toEqual([
      { prefix: '198.51.100.0/24', nextHop: '192.0.2.1' },
      { prefix: '2001:db8::/48' },
    ]);
    expect(res?.data?.status.success).toBe(true);
  });

  it('surfaces a refused announce', async () => {
    stubControlPlane({
      'POST /api/v1/gateway/bgp/prefixes': refused(400, 'invalid prefix'),
    });
    const { result } = renderBGP();
    let res: Awaited<ReturnType<typeof result.current.announce>> | undefined;
    await act(async () => {
      res = await result.current.announce('not-a-prefix');
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(400);
  });

  it('withdraws a prefix by query', async () => {
    const sent = stubControlPlane({
      'DELETE /api/v1/gateway/bgp/prefixes': ok({ status: { success: true, message: 'withdrawn' } }),
    });
    const { result } = renderBGP();
    let res: Awaited<ReturnType<typeof result.current.withdraw>> | undefined;
    await act(async () => {
      res = await result.current.withdraw('198.51.100.0/24');
    });
    expect(res?.data?.status.success).toBe(true);
    expect(sent[0]).toMatchObject({ method: 'DELETE', path: '/api/v1/gateway/bgp/prefixes' });
    const input = vi.mocked(fetch).mock.calls.at(-1)![0];
    const u = new URL(input instanceof Request ? input.url : String(input));
    expect(u.searchParams.get('prefix')).toBe('198.51.100.0/24');
  });

  it('lists the announced prefixes', async () => {
    stubControlPlane({
      'GET /api/v1/gateway/bgp/prefixes': ok({
        prefixes: [{ prefix: '198.51.100.0/24', nextHop: '192.0.2.1', announcedAt: '2026-11-21T10:00:00Z' }],
      }),
    });
    const { result } = renderBGP();
    let res: Awaited<ReturnType<typeof result.current.listAnnounced>> | undefined;
    await act(async () => {
      res = await result.current.listAnnounced();
    });
    expect(res?.data?.prefixes[0].prefix).toBe('198.51.100.0/24');
  });

  it('normalizes prefixes', () => {
    expect(normalizePrefix(' 203.0.113.0/24 ')).toBe('203.0.113.0/24');
    expect(normalizePrefix('2001:db8::/48')).toBe('2001:db8::/48');
    expect(normalizePrefix('203.0.113.0/33')).toBeNull();
    expect(normalizePrefix('203.0.113.0')).toBeNull();
    expect(normalizePrefix('2001:db8::/129')).toBeNull();
    expect(normalizePrefix('')).toBeNull();
  });
});
