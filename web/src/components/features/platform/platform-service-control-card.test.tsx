import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { PlatformServiceControlCard } from './platform-service-control-card';

// #2047: the card lists the daemon's services through the SDK API client at
// the served /v1/platform/services routes (ListServices, GetServiceStatus),
// and a refusal reaches the operator verbatim.

const LIST = 'GET /api/v1/platform/services';
const CAPS = 'GET /api/v1/capabilities';

const SERVICE_OPS = [
  'POST /api/v1/platform/services/{service}/start',
  'POST /api/v1/platform/services/{service}/stop',
  'POST /api/v1/platform/services/{service}/restart',
] as const;

// The server's capabilities listing: every service op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = SERVICE_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: services' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}
const TPM = 'GET /api/v1/platform/services/tpm';

function baseList(): Answer {
  return ok({
    services: [
      { name: 'tpm', status: 'running', uptime: '1h2m0s', start_count: 1 },
      { name: 'dns', status: 'error', last_error: 'bind: address in use' },
    ],
    count: 2,
    timestamp: 1,
  });
}

function listGets(sent: { method: string; path: string }[]) {
  return sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/platform/services').length;
}

describe('PlatformServiceControlCard capability gates', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('start, stop and restart are disabled when the server does not enable them', async () => {
    stubControlPlane({ [CAPS]: caps([...SERVICE_OPS]), [LIST]: baseList() });
    render(withControlPlane(<PlatformServiceControlCard />));
    const row = await screen.findByTestId('service-row-tpm');

    for (const name of ['Start tpm', 'Stop tpm', 'Restart tpm']) {
      const button = within(row).getByRole('button', { name });
      await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('false'));
      expect((button as HTMLButtonElement).disabled).toBe(true);
    }
  });
});

describe('PlatformServiceControlCard list and detail', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('lists the services with their status', async () => {
    const sent = stubControlPlane({ [CAPS]: caps(), [LIST]: baseList() });
    render(withControlPlane(<PlatformServiceControlCard />));

    expect((await screen.findByTestId('service-status-tpm')).textContent).toBe('running');
    expect(screen.getByTestId('service-status-dns').textContent).toBe('error');
    expect(screen.getByTestId('service-row-tpm').textContent).toContain('1h2m0s');
    expect(screen.getByTestId('service-row-dns').textContent).toContain('bind: address in use');
    expect(listGets(sent)).toBe(1);
  });

  it('says when no service is registered', async () => {
    stubControlPlane({ [CAPS]: caps(), [LIST]: ok({ services: [], count: 0 }) });
    render(withControlPlane(<PlatformServiceControlCard />));

    expect(await screen.findByText('No services registered.')).toBeDefined();
  });

  it('shows a list refusal verbatim', async () => {
    stubControlPlane({ [CAPS]: caps(), [LIST]: refused(404, 'service registry not configured') });
    render(withControlPlane(<PlatformServiceControlCard />));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('service registry not configured');
    expect(screen.queryByTestId('platform-services')).toBeNull();
  });

  it('re-reads on Refresh', async () => {
    const sent = stubControlPlane({ [CAPS]: caps(), [LIST]: baseList() });
    render(withControlPlane(<PlatformServiceControlCard />));
    await screen.findByTestId('service-row-tpm');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    });

    expect(listGets(sent)).toBe(2);
  });

  it("shows one service's detail", async () => {
    stubControlPlane({
      [CAPS]: caps(),
      [LIST]: baseList(),
      [TPM]: ok({
        name: 'tpm',
        status: 'running',
        started_at: '2026-11-21T00:00:00Z',
        start_count: 3,
        stop_count: 2,
      }),
    });
    render(withControlPlane(<PlatformServiceControlCard />));
    const row = await screen.findByTestId('service-row-tpm');

    await act(async () => {
      fireEvent.click(within(row).getByRole('button', { name: 'Details' }));
    });

    const detail = await screen.findByTestId('service-detail');
    expect(detail.textContent).toContain('2026-11-21T00:00:00Z');
    expect(detail.textContent).toContain('3');
    expect(detail.textContent).toContain('2');
  });
});
