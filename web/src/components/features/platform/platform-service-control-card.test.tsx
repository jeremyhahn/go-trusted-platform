import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { PlatformServiceControlCard } from './platform-service-control-card';

// #2047: the card lists the daemon's services through the SDK API client at
// the served /v1/platform/services routes (ListServices, GetServiceStatus),
// and a refusal reaches the operator verbatim.

const LIST = 'GET /api/v1/platform/services';
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

describe('PlatformServiceControlCard list and detail', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('lists the services with their status', async () => {
    const sent = stubControlPlane({ [LIST]: baseList() });
    render(withControlPlane(<PlatformServiceControlCard />));

    expect((await screen.findByTestId('service-status-tpm')).textContent).toBe('running');
    expect(screen.getByTestId('service-status-dns').textContent).toBe('error');
    expect(screen.getByTestId('service-row-tpm').textContent).toContain('1h2m0s');
    expect(screen.getByTestId('service-row-dns').textContent).toContain('bind: address in use');
    expect(listGets(sent)).toBe(1);
  });

  it('says when no service is registered', async () => {
    stubControlPlane({ [LIST]: ok({ services: [], count: 0 }) });
    render(withControlPlane(<PlatformServiceControlCard />));

    expect(await screen.findByText('No services registered.')).toBeDefined();
  });

  it('shows a list refusal verbatim', async () => {
    stubControlPlane({ [LIST]: refused(404, 'service registry not configured') });
    render(withControlPlane(<PlatformServiceControlCard />));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('service registry not configured');
    expect(screen.queryByTestId('platform-services')).toBeNull();
  });

  it('re-reads on Refresh', async () => {
    const sent = stubControlPlane({ [LIST]: baseList() });
    render(withControlPlane(<PlatformServiceControlCard />));
    await screen.findByTestId('service-row-tpm');

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    });

    expect(listGets(sent)).toBe(2);
  });

  it("shows one service's detail", async () => {
    stubControlPlane({
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
