import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { proxyPoolSummary, proxyRouteMatch, useProxy } from './use-proxy';

function renderProxy() {
  return renderHook(() => useProxy(), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

describe('useProxy', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('lists routes through GET /proxy/routes', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/proxy/routes': ok({
        routes: [{ id: 'r1', hosts: ['a.example'], pathPrefix: '/api', poolId: 'p1' }],
        version: '18446744073709551615',
      }),
    });
    const { result } = renderProxy();
    let res: Awaited<ReturnType<typeof result.current.listRoutes>> | undefined;
    await act(async () => {
      res = await result.current.listRoutes();
    });
    expect(res?.data?.routes?.[0].id).toBe('r1');
    expect(res?.data?.version).toBe('18446744073709551615');
    expect(sent).toEqual([{ method: 'GET', path: '/api/v1/proxy/routes', body: undefined }]);
  });

  it('creates a route with the { route } body', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/proxy/routes': ok({ route: { id: 'r2' }, version: '2' }),
    });
    const { result } = renderProxy();
    await act(async () => {
      await result.current.createRoute({ id: 'r2', hosts: ['b.example'], poolId: 'p1' });
    });
    expect(sent).toEqual([
      {
        method: 'POST',
        path: '/api/v1/proxy/routes',
        body: { route: { id: 'r2', hosts: ['b.example'], poolId: 'p1' } },
      },
    ]);
  });

  it('updates a pool by its escaped id', async () => {
    const sent = stubControlPlane({
      'PUT /api/v1/proxy/pools/p%201': ok({ pool: { id: 'p 1' }, version: '3' }),
    });
    const { result } = renderProxy();
    const pool = { id: 'p 1', backends: [{ url: 'https://backend-1.example:8443', weight: 1 }] };
    await act(async () => {
      await result.current.updatePool('p 1', pool);
    });
    expect(sent[0]).toEqual({
      method: 'PUT',
      path: '/api/v1/proxy/pools/p%201',
      body: { pool: { id: 'p 1', backends: [{ url: 'https://backend-1.example:8443', weight: 1 }] } },
    });
  });

  it('deletes a pool and reloads the config', async () => {
    const sent = stubControlPlane({
      'DELETE /api/v1/proxy/pools/p1': ok({ version: '4' }),
      'POST /api/v1/proxy/reload': ok({ version: '5' }),
    });
    const { result } = renderProxy();
    let res: Awaited<ReturnType<typeof result.current.reloadConfig>> | undefined;
    await act(async () => {
      await result.current.deletePool('p1');
      res = await result.current.reloadConfig();
    });
    expect(sent.map((s) => `${s.method} ${s.path}`)).toEqual([
      'DELETE /api/v1/proxy/pools/p1',
      'POST /api/v1/proxy/reload',
    ]);
    expect(sent[1].body).toEqual({});
    expect(res?.data?.version).toBe('5');
  });

  it('reads status and the zone matrix', async () => {
    stubControlPlane({
      'GET /api/v1/proxy/status': ok({ version: '5', routeCount: 2, poolCount: 1, updatedAt: '1795233143' }),
      'GET /api/v1/proxy/zone-matrix': ok({
        zones: ['mgmt', 'tenant'],
        pairs: [{ from: 'mgmt', to: 'tenant', services: [] }],
      }),
    });
    const { result } = renderProxy();
    let status: Awaited<ReturnType<typeof result.current.getStatus>> | undefined;
    let matrix: Awaited<ReturnType<typeof result.current.getZoneMatrix>> | undefined;
    await act(async () => {
      status = await result.current.getStatus();
      matrix = await result.current.getZoneMatrix();
    });
    expect(status?.data?.routeCount).toBe(2);
    expect(matrix?.data?.pairs?.[0].to).toBe('tenant');
  });

  it('surfaces a refusal', async () => {
    stubControlPlane({
      'POST /api/v1/proxy/routes': refused(409, 'proxy: route r1 already exists'),
    });
    const { result } = renderProxy();
    let res: Awaited<ReturnType<typeof result.current.createRoute>> | undefined;
    await act(async () => {
      res = await result.current.createRoute({ id: 'r1' });
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(409);
    expect(res?.error?.message).toContain('already exists');
  });

  it('summarises routes and pools', () => {
    expect(proxyRouteMatch({ hosts: ['a.example', 'b.example'], pathPrefix: '/api' })).toBe(
      'a.example, b.example /api'
    );
    expect(proxyRouteMatch({ hosts: [''] })).toBe('* /');
    expect(proxyRouteMatch({})).toBe('* /');
    expect(proxyPoolSummary({ backends: [{ url: 'https://backend-1.example' }] })).toBe('1 backend, round-robin');
    expect(proxyPoolSummary({ backends: [{}, {}], balancer: 'least-conn' })).toBe('2 backends, least-conn');
    expect(proxyPoolSummary({})).toBe('0 backends, round-robin');
  });
});
