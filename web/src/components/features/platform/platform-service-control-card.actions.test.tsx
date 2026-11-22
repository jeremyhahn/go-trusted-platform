import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { PlatformServiceControlCard } from './platform-service-control-card';

// #2047: the card starts a service at once, and stops or restarts one only
// after the operator confirms (StartService, StopService, RestartService);
// a daemon refusal reaches the operator verbatim.

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
const START = 'POST /api/v1/platform/services/tpm/start';
const STOP = 'POST /api/v1/platform/services/tpm/stop';
const RESTART = 'POST /api/v1/platform/services/tpm/restart';

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

type Sent = { method: string; path: string }[];

function listGets(sent: Sent) {
  return sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/platform/services').length;
}

function posts(sent: Sent) {
  return sent.filter((r) => r.method === 'POST');
}

async function renderCard(routes: Record<string, Answer>) {
  const sent = stubControlPlane({ [CAPS]: caps(), [LIST]: baseList(), ...routes });
  render(withControlPlane(<PlatformServiceControlCard />));
  await screen.findByTestId('service-row-tpm');
  return sent;
}

async function click(el: HTMLElement) {
  await act(async () => {
    fireEvent.click(el);
  });
}

describe('PlatformServiceControlCard actions', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('starts a service', async () => {
    const sent = await renderCard({
      [START]: ok({ service: 'tpm', action: 'start', success: true, message: 'service started successfully' }),
    });

    await click(screen.getByRole('button', { name: 'Start tpm' }));

    const toast = await screen.findByText('Service started: service started successfully');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(posts(sent).map((r) => r.path)).toEqual(['/api/v1/platform/services/tpm/start']);
    expect(listGets(sent)).toBe(2);
  });

  it('stops a service only after the confirm', async () => {
    const sent = await renderCard({
      [STOP]: ok({ service: 'tpm', action: 'stop', success: true, message: 'service stopped successfully' }),
    });

    await click(screen.getByRole('button', { name: 'Stop tpm' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Stop tpm?');
    expect(posts(sent)).toHaveLength(0);

    await click(within(dialog).getByRole('button', { name: 'Stop' }));

    expect(await screen.findByText('Service stopped: service stopped successfully')).toBeDefined();
    expect(posts(sent).map((r) => r.path)).toEqual(['/api/v1/platform/services/tpm/stop']);
  });

  it('sends nothing on Cancel', async () => {
    const sent = await renderCard({});

    await click(screen.getByRole('button', { name: 'Restart tpm' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Restart tpm?');

    await click(within(dialog).getByRole('button', { name: 'Cancel' }));

    expect(posts(sent)).toHaveLength(0);
  });

  it('restarts after the confirm', async () => {
    const sent = await renderCard({
      [RESTART]: ok({ service: 'tpm', action: 'restart', success: true, message: 'service restarted successfully' }),
    });

    await click(screen.getByRole('button', { name: 'Restart tpm' }));
    const dialog = await screen.findByRole('dialog');
    await click(within(dialog).getByRole('button', { name: 'Restart' }));

    expect(await screen.findByText('Service restarted: service restarted successfully')).toBeDefined();
    expect(posts(sent).map((r) => r.path)).toEqual(['/api/v1/platform/services/tpm/restart']);
  });

  it('shows a 409 refusal verbatim', async () => {
    const sent = await renderCard({
      [STOP]: refused(409, 'service tpm is not controllable: owned by the process'),
    });

    await click(screen.getByRole('button', { name: 'Stop tpm' }));
    const dialog = await screen.findByRole('dialog');
    await click(within(dialog).getByRole('button', { name: 'Stop' }));

    const toast = await screen.findByText('Stop failed: service tpm is not controllable: owned by the process');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(listGets(sent)).toBe(1);
  });
});
