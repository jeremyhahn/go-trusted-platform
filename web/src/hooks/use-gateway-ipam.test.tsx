import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { useGatewayIPAM, type GatewayIPAllocation } from './use-gateway-ipam';

const PATH = '/api/v1/gateway/ipam/allocations';

const A1 = { ip: '10.0.0.10', poolId: 'pool-a', hostname: 'node-a', allocatedAt: '2026-11-20T00:00:00Z' };
const A2 = { ip: '10.0.0.11', poolId: 'pool-a', allocatedAt: '2026-11-21T00:00:00Z' };

const allocated: Answer = {
  status: 201,
  body: { code: 201, success: true, payload: { status: { success: true, message: 'allocated' }, allocation: A2 } },
};

const urls = () =>
  vi.mocked(fetch).mock.calls.map(([input]) => String(input instanceof Request ? input.url : input));

function render(poolId?: string) {
  return renderHook(() => useGatewayIPAM(poolId), {
    wrapper: ({ children }) => withControlPlane(children),
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('useGatewayIPAM', () => {
  it("lists every pool's allocations through GET /gateway/ipam/allocations", async () => {
    const sent = stubControlPlane({ [`GET ${PATH}`]: ok({ allocations: [A1] }) });
    const { result } = render();

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.allocations).toEqual([A1]);
    expect(result.current.error).toBeNull();
    expect(sent).toContainEqual({ method: 'GET', path: PATH, body: undefined });
    expect(urls().some((u) => u.includes('poolId'))).toBe(false);
  });

  it('filters by pool with ?poolId=', async () => {
    stubControlPlane({ [`GET ${PATH}`]: ok({ allocations: [A1] }) });
    const { result } = render('pool-a');

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(urls().some((u) => u.endsWith(`${PATH}?poolId=pool-a`))).toBe(true);
  });

  it('shows a refused list as error', async () => {
    stubControlPlane({ [`GET ${PATH}`]: refused(403, 'forbidden') });
    const { result } = render();

    await waitFor(() => expect(result.current.error).toBe('HTTP 403: forbidden'));
    expect(result.current.allocations).toEqual([]);
    expect(result.current.isLoading).toBe(false);
  });

  it('allocates through POST and lists again', async () => {
    const sent = stubControlPlane({
      [`GET ${PATH}`]: ok({ allocations: [A1] }),
      [`POST ${PATH}`]: allocated,
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    let got: GatewayIPAllocation | undefined;
    await act(async () => {
      got = await result.current.allocate({ poolId: 'pool-a', hostname: 'node-b', deviceId: 'dev-1' });
    });

    expect(got).toEqual(A2);
    const post = sent.findIndex((r) => r.method === 'POST');
    expect(sent[post]).toEqual({
      method: 'POST',
      path: PATH,
      body: { poolId: 'pool-a', hostname: 'node-b', deviceId: 'dev-1' },
    });
    expect(sent.slice(post + 1)).toContainEqual({ method: 'GET', path: PATH, body: undefined });
  });

  it('releases through DELETE with ?ip= and lists again', async () => {
    const sent = stubControlPlane({
      [`GET ${PATH}`]: ok({ allocations: [A1] }),
      [`DELETE ${PATH}`]: ok({ status: { success: true, message: 'released' } }),
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await act(() => result.current.release('10.0.0.10'));

    const del = sent.findIndex((r) => r.method === 'DELETE');
    expect(del).toBeGreaterThanOrEqual(0);
    expect(sent[del].path).toBe(PATH);
    expect(sent.slice(del + 1)).toContainEqual({ method: 'GET', path: PATH, body: undefined });
    expect(urls().some((u) => u.endsWith('?ip=10.0.0.10'))).toBe(true);
  });

  it('rejects a refused allocate with the HTTP status', async () => {
    const sent = stubControlPlane({
      [`GET ${PATH}`]: ok({ allocations: [A1] }),
      [`POST ${PATH}`]: refused(409, 'pool exhausted'),
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await act(async () => {
      await expect(result.current.allocate({ poolId: 'pool-a', deviceId: 'dev-1' })).rejects.toThrow('HTTP 409: pool exhausted');
    });

    const post = sent.findIndex((r) => r.method === 'POST');
    expect(post).toBeGreaterThanOrEqual(0);
    expect(sent[post].body).toMatchObject({ deviceId: 'dev-1' });
    expect(sent.slice(post + 1).some((r) => r.method === 'GET')).toBe(false);
  });
});

describe('useGatewayIPAM stale reads', () => {
  const B1 = { ip: '198.51.100.10', poolId: 'pool-b', allocatedAt: '2026-11-21T00:00:00Z' };

  interface Pending {
    poolId: string | null;
    resolve: (allocations: unknown[]) => void;
  }

  /** stubDeferred answers each list GET with a promise the test resolves by hand. */
  function stubDeferred(): Pending[] {
    const pending: Pending[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(input instanceof Request ? input.url : String(input));
        const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
        const respond = (status: number, body: unknown) =>
          new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
        if (method === 'POST' && url.pathname === PATH) {
          return Promise.resolve(respond(allocated.status, allocated.body));
        }
        if (method === 'GET' && url.pathname === PATH) {
          return new Promise<Response>((resolve) => {
            pending.push({
              poolId: url.searchParams.get('poolId'),
              resolve: (allocations) =>
                resolve(respond(200, { code: 200, success: true, payload: { allocations } })),
            });
          });
        }
        return Promise.resolve(respond(404, { code: 404, success: false, error: 'no route' }));
      })
    );
    return pending;
  }

  const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

  it('a mutation refetch for the old pool does not overwrite the new pool', async () => {
    const pending = stubDeferred();
    const { result, rerender } = renderHook(({ p }: { p: string }) => useGatewayIPAM(p), {
      initialProps: { p: 'pool-a' },
      wrapper,
    });
    await waitFor(() => expect(pending).toHaveLength(1));
    await act(async () => pending[0].resolve([A1]));
    await waitFor(() => expect(result.current.allocations).toEqual([A1]));

    let done!: Promise<unknown>;
    act(() => {
      done = result.current.allocate({ poolId: 'pool-a', deviceId: 'dev-1' });
    });
    await waitFor(() => expect(pending).toHaveLength(2));
    expect(pending[1].poolId).toBe('pool-a');

    rerender({ p: 'pool-b' });
    await waitFor(() => expect(pending).toHaveLength(3));
    expect(pending[2].poolId).toBe('pool-b');
    await act(async () => pending[2].resolve([B1]));
    await waitFor(() => expect(result.current.allocations).toEqual([B1]));

    await act(async () => {
      pending[1].resolve([A1, A2]);
      await done;
    });
    expect(result.current.allocations).toEqual([B1]);
  });

  it('an older refetch resolving last does not replace a newer one', async () => {
    const pending = stubDeferred();
    const { result } = renderHook(() => useGatewayIPAM('pool-a'), { wrapper });
    await waitFor(() => expect(pending).toHaveLength(1));
    await act(async () => pending[0].resolve([]));

    let first!: Promise<void>;
    let second!: Promise<void>;
    act(() => {
      first = result.current.refetch();
      second = result.current.refetch();
    });
    await waitFor(() => expect(pending).toHaveLength(3));

    await act(async () => {
      pending[2].resolve([A1, A2]);
      await second;
    });
    await act(async () => {
      pending[1].resolve([A1]);
      await first;
    });
    expect(result.current.allocations).toEqual([A1, A2]);
  });
});
