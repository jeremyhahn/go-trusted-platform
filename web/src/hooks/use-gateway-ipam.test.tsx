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
      got = await result.current.allocate({ poolId: 'pool-a', hostname: 'node-b' });
    });

    expect(got).toEqual(A2);
    const post = sent.findIndex((r) => r.method === 'POST');
    expect(sent[post]).toEqual({ method: 'POST', path: PATH, body: { poolId: 'pool-a', hostname: 'node-b' } });
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
      await expect(result.current.allocate({ poolId: 'pool-a' })).rejects.toThrow('HTTP 409: pool exhausted');
    });

    const post = sent.findIndex((r) => r.method === 'POST');
    expect(post).toBeGreaterThanOrEqual(0);
    expect(sent.slice(post + 1).some((r) => r.method === 'GET')).toBe(false);
  });
});
