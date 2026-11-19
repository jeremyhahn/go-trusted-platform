import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { useGatewayBgp } from './use-gateway-bgp';

type Reply = { ok: boolean; status: number; text: () => Promise<string> };

function reply(body: unknown): Reply {
  return { ok: true, status: 200, text: async () => JSON.stringify(body) };
}

function bodyFor(url: string, allocations: unknown[]): unknown {
  if (url.includes('/bgp/peers')) return { peers: [] };
  if (url.includes('/bgp/prefixes')) return { prefixes: [] };
  return { allocations };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('useGatewayBgp request ordering', () => {
  it('keeps the post-mutation load when the older mount load lands last', async () => {
    const held: Array<() => void> = [];
    let mountPhase = true;
    const after = [{ ip: '10.0.0.5', pool_id: 'p1', hostname: 'h' }];
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string, init?: RequestInit) => {
        if (mountPhase && (init?.method ?? 'GET') === 'GET') {
          // Hold the mount GETs until after the mutation's refetch lands.
          return new Promise<Reply>((resolve) => {
            held.push(() => resolve(reply(bodyFor(url, []))));
          });
        }
        if (init?.method === 'POST') {
          return Promise.resolve(reply({ allocation: after[0] }));
        }
        return Promise.resolve(reply(bodyFor(url, after)));
      })
    );

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
  });

  it('applies only the newest of two overlapping refetches', async () => {
    const pending: Array<{ url: string; resolve: (r: Reply) => void }> = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (url: string) =>
          new Promise<Reply>((resolve) => {
            pending.push({ url, resolve });
          })
      )
    );

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
      pending.slice(6).forEach((p) => p.resolve(reply(bodyFor(p.url, [{ ip: 'new' }]))));
      await second;
    });
    expect(result.current.allocations.map((a) => a.ip)).toEqual(['new']);

    await act(async () => {
      pending.slice(0, 6).forEach((p) => p.resolve(reply(bodyFor(p.url, [{ ip: 'old' }]))));
      await first;
    });
    expect(result.current.allocations.map((a) => a.ip)).toEqual(['new']);
  });
});
