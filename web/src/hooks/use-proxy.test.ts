import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { parseBackends, useProxy } from './use-proxy';

vi.mock('trusted-platform-sdk', async (importOriginal) => {
  const sdk = await importOriginal<typeof import('trusted-platform-sdk')>();
  // Built per render so it binds the fetch each test stubs.
  return { ...sdk, usePlatformClient: () => new sdk.PlatformClient({ baseUrl: 'http://platform.test' }) };
});

interface Seen {
  url: string;
  method: string;
  body: unknown;
}

function stubFetch(reply: (url: string, method: string) => { status: number; json: unknown }): Seen[] {
  const seen: Seen[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      seen.push({ url, method, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      const r = reply(url, method);
      return new Response(JSON.stringify(r.json), { status: r.status });
    })
  );
  return seen;
}

const path = (u: string) => u.replace(/^https?:\/\/[^/]+/, '').replace(/^\/api/, '');

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('useProxy', () => {
  it('sends each of the 14 operations to its REST route', async () => {
    const seen = stubFetch(() => ({ status: 200, json: {} }));
    const { result } = renderHook(() => useProxy());
    const route = { id: 'r1', hosts: ['a.test'], pathPrefix: '/a', poolId: 'p1' };
    const pool = { id: 'p1', backends: [{ url: 'https://10.0.0.1:8443', weight: 1 }] };
    await act(async () => {
      await result.current.listRoutes();
      await result.current.createRoute(route);
      await result.current.getRoute('r1');
      await result.current.updateRoute('r1', route);
      await result.current.deleteRoute('r1');
      await result.current.listPools();
      await result.current.createPool(pool);
      await result.current.getPool('p1');
      await result.current.updatePool('p1', pool);
      await result.current.deletePool('p1');
      await result.current.getConfig();
      await result.current.reloadConfig();
      await result.current.getStatus();
      await result.current.getZoneMatrix();
    });
    expect(seen.map((s) => `${s.method} ${path(s.url)}`)).toEqual([
      'GET /v1/proxy/routes',
      'POST /v1/proxy/routes',
      'GET /v1/proxy/routes/r1',
      'PUT /v1/proxy/routes/r1',
      'DELETE /v1/proxy/routes/r1',
      'GET /v1/proxy/pools',
      'POST /v1/proxy/pools',
      'GET /v1/proxy/pools/p1',
      'PUT /v1/proxy/pools/p1',
      'DELETE /v1/proxy/pools/p1',
      'GET /v1/proxy/config',
      'POST /v1/proxy/config/reload',
      'GET /v1/proxy/status',
      'GET /v1/proxy/zone-matrix',
    ]);
    expect(seen[1].body).toEqual(route);
    expect(seen[8].body).toEqual(pool);
  });

  it('escapes the id in the path', async () => {
    const seen = stubFetch(() => ({ status: 200, json: {} }));
    const { result } = renderHook(() => useProxy());
    await act(async () => {
      await result.current.getRoute('a/b c');
    });
    expect(path(seen[0].url)).toBe('/v1/proxy/routes/a%2Fb%20c');
  });

  it('reports a server refusal as an unsuccessful response', async () => {
    stubFetch(() => ({ status: 404, json: { success: false, error: 'proxy route "x" not found' } }));
    const { result } = renderHook(() => useProxy());
    let res: { success: boolean } | undefined;
    await act(async () => {
      res = await result.current.getRoute('x');
    });
    expect(res?.success).toBe(false);
  });
});

describe('parseBackends', () => {
  it('splits comma and newline separated URLs with weight 1', () => {
    expect(parseBackends('https://a:1, https://b:2\nhttps://c:3\n')).toEqual([
      { url: 'https://a:1', weight: 1 },
      { url: 'https://b:2', weight: 1 },
      { url: 'https://c:3', weight: 1 },
    ]);
  });

  it('reads an optional =weight suffix', () => {
    expect(parseBackends('https://a:1=5')).toEqual([{ url: 'https://a:1', weight: 5 }]);
  });
});
