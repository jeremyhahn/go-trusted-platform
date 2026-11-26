import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { PlatformProbesCard } from './platform-probes-card';

// #2047: the probes card on the System Health page shows the platform
// status, liveness and readiness, each refused read in its own row.

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

describe('PlatformProbesCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows status, liveness and readiness', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<PlatformProbesCard />));

    await waitFor(() => expect(screen.getByTestId('probe-status').textContent).toContain('ready'));
    expect(screen.getByTestId('probe-status').textContent).toContain('linux/amd64, 4 CPUs, up 1h0m0s');
    await waitFor(() => expect(screen.getByTestId('probe-liveness').textContent).toBe('Alive'));
    await waitFor(() => expect(screen.getByTestId('probe-readiness').textContent).toBe('Not ready (unhealthy)'));
  });

  it('shows a refused read in its row', async () => {
    const r = routes();
    r[READINESS] = refused(404, 'not found');
    stubControlPlane(r);
    render(withControlPlane(<PlatformProbesCard />));

    const alert = await screen.findByTestId('probe-readiness-error');
    expect(alert.getAttribute('role')).toBe('alert');
    expect(alert.textContent).toContain('HTTP 404');
    await waitFor(() => expect(screen.getByTestId('probe-liveness').textContent).toBe('Alive'));
  });

  it('refresh reads again', async () => {
    const r = routes();
    stubControlPlane(r);
    render(withControlPlane(<PlatformProbesCard />));

    await waitFor(() => expect(screen.getByTestId('probe-readiness').textContent).toBe('Not ready (unhealthy)'));
    r[READINESS] = ok({ ready: true, status: 'healthy', timestamp: '2026-11-01T00:00:01Z' });
    await act(async () => {
      fireEvent.click(screen.getByTestId('probe-refresh'));
    });
    await waitFor(() => expect(screen.getByTestId('probe-readiness').textContent).toBe('Ready (healthy)'));
  });
});
