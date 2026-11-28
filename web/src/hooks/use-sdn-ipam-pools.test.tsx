import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { useSDNIPAMPools } from './use-sdn-ipam-pools';

// #2051: the IPAM page's pools go through SDNService on
// /api/v1/sdn/gateway/ipam/pools, not a hand-written fetch.
const PATH = '/api/v1/sdn/gateway/ipam/pools';
const ALLOCATIONS = '/api/v1/sdn/gateway/ipam/allocations';

const P1 = { id: 'pool-a', name: 'pool-a', cidr: '192.0.2.0/25', zone: 'control-plane', total: 126, allocated: 1, available: 125 };
const P2 = { id: 'pool-b', name: 'pool-b', cidr: '192.0.2.128/25', total: 126, allocated: 0, available: 126 };

const urls = () =>
  vi.mocked(fetch).mock.calls.map(([input]) => String(input instanceof Request ? input.url : input));

function render(zone?: string) {
  return renderHook(() => useSDNIPAMPools(zone), {
    wrapper: ({ children }) => withControlPlane(children),
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('useSDNIPAMPools', () => {
  it('lists every pool through GET /sdn/gateway/ipam/pools', async () => {
    const sent = stubControlPlane({ [`GET ${PATH}`]: ok({ pools: [P1, P2], count: 2 }) });
    const { result } = render();

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.pools).toEqual([P1, P2]);
    expect(result.current.error).toBeNull();
    expect(sent).toContainEqual({ method: 'GET', path: PATH, body: undefined });
    expect(urls().some((u) => u.includes('zone='))).toBe(false);
  });

  it('filters by zone with ?zone=', async () => {
    stubControlPlane({ [`GET ${PATH}`]: ok({ pools: [P1], count: 1 }) });
    const { result } = render('control-plane');

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.pools).toEqual([P1]);
    expect(urls().some((u) => u.includes(`${PATH}?zone=control-plane`))).toBe(true);
  });

  it('reports a refused list as the error with the HTTP status', async () => {
    // A 403 is not retried by the SDK client, so the refusal lands at once.
    stubControlPlane({ [`GET ${PATH}`]: refused(403, 'not permitted') });
    const { result } = render();

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.pools).toEqual([]);
    expect(result.current.error).toBe('HTTP 403: not permitted');
  });

  it('refetch lists again', async () => {
    const sent = stubControlPlane({ [`GET ${PATH}`]: ok({ pools: [P1], count: 1 }) });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await act(() => result.current.refetch());
    expect(sent.filter((r) => r.method === 'GET' && r.path === PATH)).toHaveLength(2);
  });

  it('create POSTs the body and lists again', async () => {
    const sent = stubControlPlane({
      [`GET ${PATH}`]: ok({ pools: [P1], count: 1 }),
      [`POST ${PATH}`]: { status: 201, body: { code: 201, success: true, payload: P2 } },
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    const body = { name: 'pool-b', cidr: '192.0.2.128/25' };
    let created: unknown;
    await act(async () => {
      created = await result.current.create(body);
    });

    expect(created).toEqual(P2);
    expect(sent).toContainEqual({ method: 'POST', path: PATH, body });
    expect(sent.filter((r) => r.method === 'GET' && r.path === PATH)).toHaveLength(2);
  });

  it('update PUTs the body to the pool and lists again', async () => {
    const sent = stubControlPlane({
      [`GET ${PATH}`]: ok({ pools: [P1], count: 1 }),
      [`PUT ${PATH}/pool-a`]: ok({ ...P1, description: 'lab' }),
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    const body = { name: 'pool-a', description: 'lab' };
    await act(async () => {
      await result.current.update('pool-a', body);
    });

    expect(sent).toContainEqual({ method: 'PUT', path: `${PATH}/pool-a`, body });
    expect(sent.filter((r) => r.method === 'GET' && r.path === PATH)).toHaveLength(2);
  });

  it('remove DELETEs the pool and lists again', async () => {
    const sent = stubControlPlane({
      [`GET ${PATH}`]: ok({ pools: [P1], count: 1 }),
      [`DELETE ${PATH}/pool-a`]: ok({ resource_id: 'pool-a', resource_type: 'ipam_pool', action: 'delete', success: true }),
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await act(() => result.current.remove('pool-a'));

    expect(sent.some((r) => r.method === 'DELETE' && r.path === `${PATH}/pool-a`)).toBe(true);
    expect(sent.filter((r) => r.method === 'GET' && r.path === PATH)).toHaveLength(2);
  });

  it.each([
    ['create', (r: ReturnType<typeof useSDNIPAMPools>) => r.create({ name: 'p', cidr: '192.0.2.0/24' }), 'POST', PATH],
    ['update', (r: ReturnType<typeof useSDNIPAMPools>) => r.update('pool-a', { name: 'p' }), 'PUT', `${PATH}/pool-a`],
    ['remove', (r: ReturnType<typeof useSDNIPAMPools>) => r.remove('pool-a'), 'DELETE', `${PATH}/pool-a`],
  ])('a refused %s rejects with HTTP <status>: <message>', async (_name, call, method, path) => {
    stubControlPlane({
      [`GET ${PATH}`]: ok({ pools: [P1], count: 1 }),
      [`${method} ${path}`]: refused(409, 'pool in use'),
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await expect(call(result.current)).rejects.toThrow('HTTP 409: pool in use');
  });

  it('reads one pool with get', async () => {
    const sent = stubControlPlane({
      [`GET ${PATH}`]: ok({ pools: [P1], count: 1 }),
      [`GET ${PATH}/pool-a`]: ok(P1),
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    let got: unknown;
    await act(async () => {
      got = await result.current.get('pool-a');
    });

    expect(got).toEqual(P1);
    expect(sent).toContainEqual({ method: 'GET', path: `${PATH}/pool-a`, body: undefined });
  });

  it('rejects get with the HTTP status', async () => {
    stubControlPlane({
      [`GET ${PATH}`]: ok({ pools: [P1], count: 1 }),
      [`GET ${PATH}/pool-a`]: refused(404, 'pool not found'),
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await expect(result.current.get('pool-a')).rejects.toThrow('HTTP 404: pool not found');
  });

  it("lists one pool's allocations with listAllocations", async () => {
    const allocation = { ip: '192.0.2.10', pool_id: 'pool-1', status: 'allocated', hostname: 'node.example.com' };
    const sent = stubControlPlane({
      [`GET ${PATH}`]: ok({ pools: [P1], count: 1 }),
      [`GET ${ALLOCATIONS}`]: ok({ allocations: [allocation], count: 1 }),
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    let got: unknown;
    await act(async () => {
      got = await result.current.listAllocations('pool-1');
    });

    expect(got).toEqual([allocation]);
    expect(sent.some((r) => r.method === 'GET' && r.path === ALLOCATIONS)).toBe(true);
    expect(urls().some((u) => u.includes(`${ALLOCATIONS}?pool_id=pool-1`))).toBe(true);
  });

  it('rejects listAllocations with the HTTP status', async () => {
    stubControlPlane({
      [`GET ${PATH}`]: ok({ pools: [P1], count: 1 }),
      [`GET ${ALLOCATIONS}`]: refused(403, 'not permitted'),
    });
    const { result } = render();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await expect(result.current.listAllocations('pool-1')).rejects.toThrow('HTTP 403: not permitted');
  });
});
