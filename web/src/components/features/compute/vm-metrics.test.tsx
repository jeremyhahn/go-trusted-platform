import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { VMMetricsCard } from './vm-metrics';

// #2044: the VM detail page's metrics card reads GetVMMetrics through the SDK
// client, and its Refresh control sits behind the server's capability gate.

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const METRICS_OP = 'GET /api/v1/compute/vms/{id}/metrics';
const METRICS_PATH = 'GET /api/v1/compute/vms/vm-1/metrics';

function caps(off: string[] = []): Answer {
  const capabilities = [METRICS_OP].map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: compute' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function metrics(): Answer {
  return ok({
    metrics: {
      cpuUsagePercent: 12.5,
      memoryUsedMb: 512,
      memoryAvailableMb: 1536,
      diskReadBytes: 4096,
      diskWriteBytes: 8192,
      networkRxBytes: 1024,
      networkTxBytes: 2048,
      uptimeSeconds: 3600,
    },
  });
}

function metricsGets(sent: { method: string; path: string }[]): number {
  return sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/compute/vms/vm-1/metrics').length;
}

describe('VMMetricsCard', () => {
  it('shows the SDK metrics from GetVMMetrics', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps(), [METRICS_PATH]: metrics() });
    render(withControlPlane(<VMMetricsCard vmId="vm-1" />));

    const card = await screen.findByTestId('vm-metrics');
    await waitFor(() => {
      expect(card.textContent).toContain('12.5');
      expect(card.textContent).toContain('512');
    });
  });

  it('re-sends the GET on Refresh metrics', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps(), [METRICS_PATH]: metrics() });
    render(withControlPlane(<VMMetricsCard vmId="vm-1" />));
    await waitFor(() => expect(metricsGets(sent)).toBe(1));

    await waitFor(() => {
      expect((screen.getByRole('button', { name: 'Refresh metrics' }) as HTMLButtonElement).disabled).toBe(false);
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Refresh metrics' }));
    });

    await waitFor(() => expect(metricsGets(sent)).toBe(2));
  });

  it('shows a refused GET as an error', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [METRICS_PATH]: refused(409, 'compute: vm is not running'),
    });
    render(withControlPlane(<VMMetricsCard vmId="vm-1" />));

    const error = await screen.findByTestId('vm-metrics-error');
    expect(error.textContent).toContain('vm is not running');
  });

  it('withholds Refresh metrics when the server does not offer it', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps([METRICS_OP]), [METRICS_PATH]: metrics() });
    render(withControlPlane(<VMMetricsCard vmId="vm-1" />));

    await waitFor(() => {
      const refresh = screen.getByRole('button', { name: 'Refresh metrics' }) as HTMLButtonElement;
      expect(refresh.getAttribute('data-capability-enabled')).toBe('false');
      expect(refresh.disabled).toBe(true);
      expect(refresh.title).toBe('not-configured: compute');
    });
  });
});
