import type { ReactNode } from 'react';
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PlatformService } from 'trusted-platform-sdk';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { usePlatformServices } from './use-platform-services';

// #2047: the daemon services hook lists, reads, starts, stops and restarts
// the services through the SDK PlatformService, not hand-built API paths.

const LIST = 'GET /api/v1/platform/services';
const ONE = 'GET /api/v1/platform/services/dns';
const START = 'POST /api/v1/platform/services/dns/start';
const STOP = 'POST /api/v1/platform/services/dns/stop';
const RESTART = 'POST /api/v1/platform/services/dns/restart';

function actionAnswer(action: string): Answer {
  return ok({ service: 'dns', action, success: true, message: 'ok' });
}

function routes(): Record<string, Answer> {
  return {
    [LIST]: ok({
      services: [{ name: 'dns', status: 'running', started_at: '2026-11-01T00:00:00Z', start_count: 1, stop_count: 0 }],
      count: 1,
      timestamp: 1,
    }),
    [ONE]: ok({ name: 'dns', status: 'running', start_count: 1, stop_count: 0 }),
    [START]: actionAnswer('start'),
    [STOP]: actionAnswer('stop'),
    [RESTART]: actionAnswer('restart'),
  };
}

const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

describe('usePlatformServices', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('lists the services through PlatformService.listServices', async () => {
    const sent = stubControlPlane(routes());
    const spy = vi.spyOn(PlatformService.prototype, 'listServices');
    const { result } = renderHook(() => usePlatformServices(), { wrapper });

    let answer: Awaited<ReturnType<typeof result.current.listServices>> | undefined;
    await act(async () => {
      answer = await result.current.listServices();
    });

    expect(answer?.data?.services?.[0].name).toBe('dns');
    expect(answer?.data?.count).toBe(1);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(sent.map((r) => `${r.method} ${r.path}`)).toEqual([LIST]);
  });

  it('reads one service through PlatformService.getServiceStatus', async () => {
    stubControlPlane(routes());
    const spy = vi.spyOn(PlatformService.prototype, 'getServiceStatus');
    const { result } = renderHook(() => usePlatformServices(), { wrapper });

    let answer: Awaited<ReturnType<typeof result.current.getService>> | undefined;
    await act(async () => {
      answer = await result.current.getService('dns');
    });

    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith('dns');
    expect(answer?.data?.status).toBe('running');
  });

  it('sends start, stop and restart through their SDK methods, once each', async () => {
    const sent = stubControlPlane(routes());
    const start = vi.spyOn(PlatformService.prototype, 'startService');
    const stop = vi.spyOn(PlatformService.prototype, 'stopService');
    const restart = vi.spyOn(PlatformService.prototype, 'restartService');
    const { result } = renderHook(() => usePlatformServices(), { wrapper });

    await act(async () => {
      await result.current.act('dns', 'start');
      await result.current.act('dns', 'stop');
      await result.current.act('dns', 'restart');
    });

    for (const spy of [start, stop, restart]) {
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy).toHaveBeenCalledWith('dns');
    }
    expect(sent.map((r) => `${r.method} ${r.path}`).filter((p) => p.startsWith('POST '))).toEqual([
      START,
      STOP,
      RESTART,
    ]);
  });

  it('returns a refused action as the server error', async () => {
    const r = routes();
    r[STOP] = refused(409, 'service dns is not running');
    const sent = stubControlPlane(r);
    const { result } = renderHook(() => usePlatformServices(), { wrapper });

    let answer: Awaited<ReturnType<typeof result.current.act>> | undefined;
    await act(async () => {
      answer = await result.current.act('dns', 'stop');
    });

    expect(answer?.error?.message).toContain('not running');
    expect(answer?.data).toBeUndefined();
    expect(sent.filter((s) => `${s.method} ${s.path}` === STOP)).toHaveLength(1);
  });
});
