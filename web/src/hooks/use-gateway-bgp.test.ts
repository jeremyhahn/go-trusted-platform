import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

const seen = vi.hoisted(() => [] as Array<{ op: string; args: unknown[] }>);
const replies = vi.hoisted(() => new Map<string, unknown>());

const gateway = vi.hoisted(() => {
  const op =
    (name: string) =>
    (...args: unknown[]) => {
      seen.push({ op: name, args });
      return Promise.resolve(replies.get(name) ?? { success: true, data: {} });
    };
  return {
    listBGPPeers: op('listBGPPeers'),
    listAnnouncedPrefixes: op('listAnnouncedPrefixes'),
    announcePrefix: op('announcePrefix'),
    withdrawPrefix: op('withdrawPrefix'),
    allocateIP: op('allocateIP'),
    releaseIP: op('releaseIP'),
    listAllocations: op('listAllocations'),
  };
});

vi.mock('trusted-platform-sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('trusted-platform-sdk')>()),
  useGateway: () => gateway,
}));

import { toAllocation, toPeer, toPrefix, unwrapPayload, useGatewayBgp } from './use-gateway-bgp';

const fetchSpy = vi.fn(() => Promise.reject(new Error('hand-written fetch')));

afterEach(() => {
  cleanup();
  seen.length = 0;
  replies.clear();
  fetchSpy.mockClear();
  vi.unstubAllGlobals();
});

describe('use-gateway-bgp field mapping', () => {
  it('reads a peer in camelCase and in proto names', () => {
    expect(toPeer({ address: 'a', asn: 64513, state: 'established', prefixesReceived: 4 })).toEqual({
      address: 'a',
      asn: 64513,
      state: 'established',
      prefixesReceived: 4,
    });
    expect(toPeer({ address: 'b', asn: '64514', prefixes_received: '7' })).toEqual({
      address: 'b',
      asn: 64514,
      state: '',
      prefixesReceived: 7,
    });
  });

  it('reads a prefix next hop in either name', () => {
    expect(toPrefix({ prefix: 'p', nextHop: 'n1' }).nextHop).toBe('n1');
    expect(toPrefix({ prefix: 'p', next_hop: 'n2' }).nextHop).toBe('n2');
    expect(toPrefix({ prefix: 'p' }).nextHop).toBe('');
  });

  it('reads an allocation pool id in either name', () => {
    expect(toAllocation({ ip: 'i', poolId: 'p1', hostname: 'h', status: 'active' })).toEqual({
      ip: 'i',
      poolId: 'p1',
      deviceId: '',
      hostname: 'h',
      status: 'active',
    });
    expect(toAllocation({ ip: 'i', pool_id: 'p2' }).poolId).toBe('p2');
    expect(toAllocation({ ip: 'i', deviceId: 'd1' }).deviceId).toBe('d1');
    expect(toAllocation({ ip: 'i', device_id: 'd2' }).deviceId).toBe('d2');
  });

  it('unwraps the REST envelope payload', () => {
    expect(unwrapPayload({ code: 200, success: true, payload: { peers: [] } })).toEqual({ peers: [] });
    expect(unwrapPayload({ code: 503, success: false, error: 'x', payload: null })).toBeNull();
    expect(unwrapPayload({ peers: [] })).toEqual({ peers: [] });
  });
});

describe('useGatewayBgp through the SDK gateway service', () => {
  it('loads peers, prefixes and allocations with the SDK, never fetch', async () => {
    vi.stubGlobal('fetch', fetchSpy);
    replies.set('listBGPPeers', { success: true, data: { peers: [{ address: '192.0.2.1', asn: 64512, state: 'established' }] } });
    replies.set('listAnnouncedPrefixes', { success: true, data: { prefixes: [{ prefix: '10.0.0.0/24', nextHop: '192.0.2.2' }] } });
    replies.set('listAllocations', { success: true, data: { allocations: [{ ip: '10.0.0.5', poolId: 'p1' }] } });

    const { result } = renderHook(() => useGatewayBgp());
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    expect(seen.map((s) => s.op).sort()).toEqual(['listAllocations', 'listAnnouncedPrefixes', 'listBGPPeers']);
    expect(result.current.peers.map((p) => p.address)).toEqual(['192.0.2.1']);
    expect(result.current.prefixes).toEqual([{ prefix: '10.0.0.0/24', nextHop: '192.0.2.2' }]);
    expect(result.current.allocations.map((a) => a.ip)).toEqual(['10.0.0.5']);
    expect(result.current.errors).toEqual({ peers: null, prefixes: null, allocations: null });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('sends each mutation through its SDK method', async () => {
    vi.stubGlobal('fetch', fetchSpy);
    replies.set('allocateIP', { success: true, data: { allocation: { ip: '10.0.0.9', poolId: 'p1', deviceId: 'd1', hostname: 'h' } } });
    const { result } = renderHook(() => useGatewayBgp());
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    seen.length = 0;

    let alloc: unknown;
    await act(async () => {
      await result.current.announcePrefix('10.1.0.0/24', '192.0.2.2');
      await result.current.withdrawPrefix('10.1.0.0/24');
      alloc = await result.current.allocateIP('p1', 'd1', 'h');
      await result.current.releaseIP('10.0.0.9');
    });

    const mutations = seen.filter((s) => !s.op.startsWith('list'));
    expect(mutations).toEqual([
      { op: 'announcePrefix', args: [{ prefix: '10.1.0.0/24', nextHop: '192.0.2.2' }] },
      { op: 'withdrawPrefix', args: [{ prefix: '10.1.0.0/24' }] },
      { op: 'allocateIP', args: [{ poolId: 'p1', deviceId: 'd1', hostname: 'h' }] },
      { op: 'releaseIP', args: [{ ip: '10.0.0.9' }] },
    ]);
    expect(alloc).toEqual({ ip: '10.0.0.9', poolId: 'p1', deviceId: 'd1', hostname: 'h', status: '' });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('throws the SDK error message of a failed mutation and reports a failed section', async () => {
    replies.set('listBGPPeers', {
      success: false,
      error: { code: 'SERVICE_UNAVAILABLE', message: 'gateway service not configured', status: 503 },
    });
    replies.set('withdrawPrefix', { success: false, error: { code: 'NOT_FOUND', message: 'prefix not announced' } });
    const { result } = renderHook(() => useGatewayBgp());
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.errors.peers).toBe('gateway service not configured');
    expect(result.current.errors.prefixes).toBeNull();

    await expect(result.current.withdrawPrefix('10.9.0.0/24')).rejects.toThrow('prefix not announced');
  });
});
