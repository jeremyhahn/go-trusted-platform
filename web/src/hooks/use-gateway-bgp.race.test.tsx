import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

type Reply = { success: boolean; data?: unknown };
type Impl = (op: string, args: unknown[]) => Promise<Reply>;

const sdk = vi.hoisted(() => ({
  impl: null as null | ((op: string, args: unknown[]) => Promise<{ success: boolean; data?: unknown }>),
}));

const gateway = vi.hoisted(() => {
  const op =
    (name: string) =>
    (...args: unknown[]) =>
      sdk.impl ? sdk.impl(name, args) : Promise.resolve({ success: true, data: {} });
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

import { useGatewayBgp } from './use-gateway-bgp';

const READS = new Set(['listBGPPeers', 'listAnnouncedPrefixes', 'listAllocations']);

function reply(data: unknown): Reply {
  return { success: true, data };
}

function bodyFor(op: string, allocations: unknown[]): unknown {
  if (op === 'listBGPPeers') return { peers: [] };
  if (op === 'listAnnouncedPrefixes') return { prefixes: [] };
  return { allocations };
}

function serve(impl: Impl) {
  sdk.impl = impl;
}

afterEach(() => {
  cleanup();
  sdk.impl = null;
});

describe('useGatewayBgp request ordering', () => {
  it('keeps the post-mutation load when the older mount load lands last', async () => {
    const held: Array<() => void> = [];
    let mountPhase = true;
    const after = [{ ip: '10.0.0.5', pool_id: 'p1', hostname: 'h' }];
    serve((op) => {
      if (mountPhase && READS.has(op)) {
        // Hold the mount reads until after the mutation's refetch lands.
        return new Promise<Reply>((resolve) => {
          held.push(() => resolve(reply(bodyFor(op, []))));
        });
      }
      if (op === 'allocateIP') {
        return Promise.resolve(reply({ allocation: after[0] }));
      }
      return Promise.resolve(reply(bodyFor(op, after)));
    });

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
    const pending: Array<{ op: string; resolve: (r: Reply) => void }> = [];
    serve(
      (op) =>
        new Promise<Reply>((resolve) => {
          pending.push({ op, resolve });
        })
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
      pending.slice(6).forEach((p) => p.resolve(reply(bodyFor(p.op, [{ ip: 'new' }]))));
      await second;
    });
    expect(result.current.allocations.map((a) => a.ip)).toEqual(['new']);

    await act(async () => {
      pending.slice(0, 6).forEach((p) => p.resolve(reply(bodyFor(p.op, [{ ip: 'old' }]))));
      await first;
    });
    expect(result.current.allocations.map((a) => a.ip)).toEqual(['new']);
  });
});
