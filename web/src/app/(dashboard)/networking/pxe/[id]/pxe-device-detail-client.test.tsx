import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import PXEDeviceDetailClient from './pxe-device-detail-client';

// #2062: the PXE device detail page reaches GetDevice, GetEvents and
// UpdateState through the real SDK client on client.pxe, each gated on its
// route in the server's capabilities listing.

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'd1' }),
  usePathname: () => '/networking/pxe/d1',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const PXE_OPS = [
  'GET /api/v1/pxe/devices/{id}',
  'GET /api/v1/pxe/devices/{id}/events',
  'PUT /api/v1/pxe/devices/{id}/state',
] as const;

// The server's capabilities listing: every PXE op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = PXE_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: pxe' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function shared(): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    'GET /api/v1/pxe/devices/d1': ok({
      device: { id: 'd1', macAddress: '02:00:00:00:00:01', state: 'ENROLLED', currentVlan: 10 },
    }),
    'GET /api/v1/pxe/devices/d1/events': ok({
      events: [
        {
          id: 'e1',
          deviceId: 'd1',
          timestamp: '2026-11-01T00:00:00Z',
          eventType: 'state_change',
          fromState: 'ENROLLING',
          toState: 'ENROLLED',
        },
      ],
    }),
  };
}

async function renderPage() {
  render(withControlPlane(<PXEDeviceDetailClient />));
  await within(await screen.findByTestId('pxe-device')).findByText('02:00:00:00:00:01');
}

function count(sent: { method: string; path: string }[], method: string, path: string) {
  return sent.filter((r) => r.method === method && r.path === path).length;
}

async function setState(state: string, reason: string) {
  fireEvent.change(screen.getByLabelText('New state'), { target: { value: state } });
  fireEvent.change(screen.getByLabelText('State reason'), { target: { value: reason } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Set state' }));
  });
}

describe('PXEDeviceDetailClient', () => {
  it('shows the device and its events', async () => {
    stubControlPlane(shared());
    await renderPage();

    const device = screen.getByTestId('pxe-device');
    expect(within(device).getByText('ENROLLED')).toBeTruthy();

    const events = screen.getByTestId('pxe-device-events');
    const row = (await within(events).findByText('state_change')).closest('tr') as HTMLElement;
    expect(within(row).getByText('ENROLLING')).toBeTruthy();
    expect(within(row).getByText('ENROLLED')).toBeTruthy();
  });

  it('sets the device state with a reason', async () => {
    const sent = stubControlPlane({
      ...shared(),
      'PUT /api/v1/pxe/devices/d1/state': ok({ device: { id: 'd1', state: 'FAILED' } }),
    });
    await renderPage();

    await setState('FAILED', 'bad image');

    await waitFor(() => {
      const put = sent.find((r) => r.method === 'PUT' && r.path === '/api/v1/pxe/devices/d1/state');
      expect(put?.body).toEqual({ state: 'PROVISIONING_STATE_FAILED', reason: 'bad image' });
    });
    await waitFor(() => {
      const toast = screen.getAllByTestId('toast').find((t) => t.textContent?.includes('FAILED'));
      expect(toast?.getAttribute('data-variant')).not.toBe('destructive');
    });
    await waitFor(() => expect(count(sent, 'GET', '/api/v1/pxe/devices/d1')).toBe(2));
  });

  it('shows a refused state change', async () => {
    stubControlPlane({
      ...shared(),
      'PUT /api/v1/pxe/devices/d1/state': refused(409, 'invalid transition'),
    });
    await renderPage();

    await setState('FAILED', 'bad image');

    await waitFor(() => {
      const toast = screen.getAllByTestId('toast').find((t) => t.textContent?.includes('invalid transition'));
      expect(toast?.getAttribute('data-variant')).toBe('destructive');
    });
  });

  it('withholds Set state when the server does not offer it', async () => {
    stubControlPlane({
      ...shared(),
      'GET /api/v1/capabilities': caps(['PUT /api/v1/pxe/devices/{id}/state']),
    });
    await renderPage();

    const button = screen.getByRole('button', { name: 'Set state' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.getAttribute('data-capability-enabled')).toBe('false');
    expect(button.getAttribute('title')).toBe('not-configured: pxe');
  });

  it('makes no device read the server does not offer', async () => {
    const sent = stubControlPlane({
      ...shared(),
      'GET /api/v1/capabilities': caps(['GET /api/v1/pxe/devices/{id}', 'GET /api/v1/pxe/devices/{id}/events']),
    });
    render(withControlPlane(<PXEDeviceDetailClient />));

    expect((await screen.findByTestId('pxe-device-not-enabled')).textContent).toContain('not-configured: pxe');
    expect(count(sent, 'GET', '/api/v1/pxe/devices/d1')).toBe(0);
    expect(count(sent, 'GET', '/api/v1/pxe/devices/d1/events')).toBe(0);
  });
});
