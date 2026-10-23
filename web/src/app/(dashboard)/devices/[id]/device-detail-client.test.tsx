import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import DeviceDetailPage from './device-detail-client';

// #250: the detail page's Enable / Disable button sends the control plane's
// lifecycle transition and re-reads the device, so the badge follows the
// recorded state; a refusal reaches the operator as a destructive toast.

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: '7' }),
  usePathname: () => '/devices/7',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const DEVICE_PATH = 'GET /api/v1/devices/7';

function storedDevice(state: string): Answer {
  return ok({ id: 7, serial: 'node-07', model: 'X10', state, created_at: '2026-10-01T00:00:00Z' });
}

async function renderPage() {
  render(withControlPlane(<DeviceDetailPage />));
  await screen.findByRole('heading', { level: 1, name: 'node-07' });
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

describe('DeviceDetailPage Enable / Disable', () => {
  beforeEach(() => {
    vi.stubGlobal('confirm', vi.fn(() => true));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('disables through POST /devices/{id}/disable and shows the Disabled badge it re-reads', async () => {
    const routes: Record<string, Answer> = {
      [DEVICE_PATH]: storedDevice('attested'),
      'POST /api/v1/devices/7/disable': ok({
        device_id: '7',
        state: 'suspended',
        previous_state: 'attested',
        reattestation_requested: false,
      }),
    };
    const sent = stubControlPlane(routes);
    await renderPage();

    // The control plane records the transition; the re-read returns it.
    routes[DEVICE_PATH] = storedDevice('suspended');
    await click('Disable');

    expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/devices/7/disable', body: {} });
    expect(sent.some((r) => r.method === 'PUT')).toBe(false);
    expect(await screen.findByRole('button', { name: 'Enable' })).toBeDefined();
    expect(screen.getByText('disabled')).toBeDefined();
  });

  it('shows the control plane refusal as a destructive toast and keeps the device as it was', async () => {
    stubControlPlane({
      [DEVICE_PATH]: storedDevice('attested'),
      'POST /api/v1/devices/7/disable': refused(400, 'device 7 has no network port on record'),
    });
    await renderPage();

    await click('Disable');

    const toast = await screen.findByText('Disable refused: device 7 has no network port on record');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.getByRole('button', { name: 'Disable' })).toBeDefined();
  });

  it('enables a suspended device through POST /devices/{id}/enable', async () => {
    const sent = stubControlPlane({
      [DEVICE_PATH]: storedDevice('suspended'),
      'POST /api/v1/devices/7/enable': ok({
        device_id: '7',
        state: 'quarantined',
        previous_state: 'suspended',
        reattestation_requested: true,
      }),
    });
    await renderPage();

    await click('Enable');

    await waitFor(() =>
      expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/devices/7/enable', body: {} })
    );
    expect(vi.mocked(confirm)).not.toHaveBeenCalled();
  });

  it('offers no transition for a revoked device', async () => {
    stubControlPlane({ [DEVICE_PATH]: storedDevice('revoked') });
    await renderPage();

    const button = screen.getByRole('button', { name: 'Disable' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.title).toMatch(/revocation is terminal/);
  });
});
