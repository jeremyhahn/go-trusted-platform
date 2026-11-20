import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// One stable client: a new object per render would re-run the hook's effects.
const gateway = {
  listBGPPeers: vi.fn(),
  listAnnouncedPrefixes: vi.fn(),
  listAllocations: vi.fn(),
  announcePrefix: vi.fn(),
  withdrawPrefix: vi.fn(),
  allocateIP: vi.fn(),
  releaseIP: vi.fn(),
};
const client = { gateway };

vi.mock('trusted-platform-sdk', () => ({ usePlatformClient: () => client }));

import { useGatewayBgp } from './use-gateway-bgp';

type Name = 'peers' | 'prefixes' | 'allocations';
type Reply = { success: true; data: unknown };

function ok(data: unknown): Reply {
  return { success: true, data };
}

function bodyFor(name: Name, allocations: unknown[]): unknown {
  if (name === 'peers') return { peers: [] };
  if (name === 'prefixes') return { prefixes: [] };
  return { allocations };
}

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => {
      throw new Error('the gateway hook must not call fetch');
    })
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe('useGatewayBgp request ordering', () => {
  it('keeps the post-mutation load when the older mount load lands last', async () => {
    const held: Array<() => void> = [];
    let mountPhase = true;
    const after = [{ ip: '10.0.0.5', poolId: 'p1', hostname: 'h' }];
    const list = (name: Name) => () => {
      if (mountPhase) {
        // Hold the mount loads until after the mutation's refetch lands.
        return new Promise<Reply>((resolve) => {
          held.push(() => resolve(ok(bodyFor(name, []))));
        });
      }
      return Promise.resolve(ok(bodyFor(name, after)));
    };
    gateway.listBGPPeers.mockImplementation(list('peers'));
    gateway.listAnnouncedPrefixes.mockImplementation(list('prefixes'));
    gateway.listAllocations.mockImplementation(list('allocations'));
    gateway.allocateIP.mockResolvedValue(ok({ allocation: after[0] }));

    const { result } = renderHook(() => useGatewayBgp());
    await waitFor(() => expect(held).toHaveLength(3));
    mountPhase = false;

    await act(async () => {
      await result.current.allocateIP('p1', 'd1', 'h');
    });
    expect(result.current.allocations.map((a) => a.ip)).toEqual(['10.0.0.5']);

    await act(async () => {
      held.forEach((release) => release());
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(result.current.allocations.map((a) => a.ip)).toEqual(['10.0.0.5']);
    expect(result.current.isLoading).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('applies only the newest of two overlapping refetches', async () => {
    const pending: Array<{ name: Name; resolve: (r: Reply) => void }> = [];
    const list = (name: Name) => () =>
      new Promise<Reply>((resolve) => {
        pending.push({ name, resolve });
      });
    gateway.listBGPPeers.mockImplementation(list('peers'));
    gateway.listAnnouncedPrefixes.mockImplementation(list('prefixes'));
    gateway.listAllocations.mockImplementation(list('allocations'));

    const { result } = renderHook(() => useGatewayBgp());
    await waitFor(() => expect(pending).toHaveLength(3));
    let first!: Promise<void>;
    let second!: Promise<void>;
    act(() => {
      first = result.current.refetch();
    });
    act(() => {
      second = result.current.refetch();
    });
    await waitFor(() => expect(pending).toHaveLength(9));

    await act(async () => {
      pending.slice(6).forEach((p) => p.resolve(ok(bodyFor(p.name, [{ ip: 'new' }]))));
      await second;
    });
    expect(result.current.allocations.map((a) => a.ip)).toEqual(['new']);

    await act(async () => {
      pending.slice(0, 6).forEach((p) => p.resolve(ok(bodyFor(p.name, [{ ip: 'old' }]))));
      await first;
    });
    expect(result.current.allocations.map((a) => a.ip)).toEqual(['new']);
    expect(fetch).not.toHaveBeenCalled();
  });
});
