import type { ReactNode } from 'react';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { usePlatformProbes } from './use-platform-probes';

// #2047: the System Health page reads GetStatus, Liveness and Readiness
// through the SDK API client; one refused read leaves the others shown.

const STATUS = 'GET /api/v1/platform/status';
const LIVENESS = 'GET /api/v1/platform/liveness';
const READINESS = 'GET /api/v1/platform/readiness';

function routes(): Record<string, Answer> {
  return {
    [STATUS]: ok({
      status: 'ready',
      version: '0.0.0-test',
      go_version: 'go1.0',
      system: { os: 'linux', arch: 'amd64', num_cpus: 4, total_memory_mb: 2048, available_memory_mb: 1024, uptime: '1h0m0s' },
      timestamp: 1,
    }),
    [LIVENESS]: ok({ alive: true, status: 'healthy', timestamp: '2026-11-01T00:00:00Z' }),
    [READINESS]: ok({ ready: false, status: 'unhealthy', timestamp: '2026-11-01T00:00:00Z' }),
  };
}

const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

describe('usePlatformProbes', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads all three probes', async () => {
    const sent = stubControlPlane(routes());
    const { result } = renderHook(() => usePlatformProbes(), { wrapper });

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    const paths = sent.map((r) => `${r.method} ${r.path}`);
    expect(paths).toContain(STATUS);
    expect(paths).toContain(LIVENESS);
    expect(paths).toContain(READINESS);
    expect(result.current.probes.readiness?.ready).toBe(false);
    expect(result.current.probes.liveness?.alive).toBe(true);
    expect(result.current.errors).toEqual({});
  });

  it('keeps the others when one is refused', async () => {
    const r = routes();
    r[LIVENESS] = refused(403, 'iam: forbidden');
    stubControlPlane(r);
    const { result } = renderHook(() => usePlatformProbes(), { wrapper });

    await waitFor(() => expect(result.current.errors.liveness).toBe('HTTP 403: iam: forbidden'));
    expect(result.current.probes.status?.status).toBe('ready');
    expect(result.current.probes.readiness?.status).toBe('unhealthy');
    expect(result.current.probes.liveness).toBeNull();
  });

  it('refetch reads again', async () => {
    const sent = stubControlPlane(routes());
    const { result } = renderHook(() => usePlatformProbes(), { wrapper });

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    await act(async () => {
      await result.current.refetch();
    });
    expect(sent.filter((r) => r.method === 'GET')).toHaveLength(6);
  });
});
