import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import { DeviceActivateCard } from './device-activate-card';

// #2048: the device page activates a device through the SDK activateDevice
// (POST /api/v1/device/activate-json, serial and mac_address on the wire),
// capability-gated; the flat answer's VLAN is shown.

const ACTIVATE_OP = 'POST /api/v1/device/activate-json';

// The server's capabilities listing for the activation op.
function caps(off = false): Answer {
  const capabilities = [
    off
      ? { op: ACTIVATE_OP, kind: 'route', enabled: false, reason: 'not-configured: device' }
      : { op: ACTIVATE_OP, kind: 'route', enabled: true },
  ];
  return ok({ capabilities, total: 1, enabled: off ? 0 : 1 });
}

function routes(overrides: Record<string, Answer> = {}): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    'POST /api/v1/device/activate-json': ok({ status: 'activated', vlan: 101, transitioned_at: '2026-01-01T00:00:00Z' }),
    ...overrides,
  };
}

const activate = () => screen.getByRole('button', { name: 'Check activation' });

async function typeMacAndActivate() {
  fireEvent.change(await screen.findByLabelText('MAC address'), { target: { value: '02:00:00:00:00:01' } });
  await waitFor(() => expect(activate().hasAttribute('disabled')).toBe(false));
  await act(async () => {
    fireEvent.click(activate());
  });
}

const posts = (sent: SentRequest[]) =>
  sent.filter((r) => r.method === 'POST' && r.path === '/api/v1/device/activate-json');

describe('DeviceActivateCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('checks the activation with the serial and MAC', async () => {
    const sent = stubControlPlane(routes());
    const onChecked = vi.fn();
    render(withControlPlane(<DeviceActivateCard serial="SN-1" onChecked={onChecked} />));

    await typeMacAndActivate();

    await waitFor(() => expect(onChecked).toHaveBeenCalledTimes(1));
    const sentPosts = posts(sent);
    expect(sentPosts).toHaveLength(1);
    expect(sentPosts[0]).toEqual({
      method: 'POST',
      path: '/api/v1/device/activate-json',
      body: { serial: 'SN-1', mac_address: '02:00:00:00:00:01' },
    });
    const result = (await screen.findByTestId('device-activate-result')).textContent ?? '';
    expect(result).toContain('Profile matched');
    expect(result).toContain('admitted VLAN 101');
    expect(result).not.toContain('activated');
    const toast = await screen.findByTestId('toast');
    expect(toast.getAttribute('data-variant')).not.toBe('destructive');
    expect(toast.textContent).toContain('Activation check');
    expect(toast.textContent).toContain('Admitted VLAN 101');
    expect(toast.textContent).not.toContain('Device activated');
  });

  it('never claims the device was activated', async () => {
    stubControlPlane(
      routes({
        'POST /api/v1/device/activate-json': ok({ status: 'activated', vlan: 101, transitioned_at: '2026-01-01T00:00:00Z' }),
      })
    );
    const onChecked = vi.fn();
    render(withControlPlane(<DeviceActivateCard serial="SN-1" onChecked={onChecked} />));

    await typeMacAndActivate();

    await waitFor(() => expect(onChecked).toHaveBeenCalledTimes(1));
    await screen.findByTestId('device-activate-result');
    expect(screen.queryByText(/Device activated/)).toBeNull();
    expect(screen.getByTestId('device-activate-card').textContent).not.toMatch(/\bactivated\b/i);
    expect(screen.getByTestId('device-activate-card').textContent).toContain('does not activate the device');
  });

  it('withholds the control the server does not offer', async () => {
    const sent = stubControlPlane(routes({ 'GET /api/v1/capabilities': caps(true) }));
    const onChecked = vi.fn();
    render(withControlPlane(<DeviceActivateCard serial="SN-1" onChecked={onChecked} />));

    fireEvent.change(await screen.findByLabelText('MAC address'), { target: { value: '02:00:00:00:00:01' } });
    await waitFor(() => expect(activate().getAttribute('title')).toBe('not-configured: device'));
    expect(activate().hasAttribute('disabled')).toBe(true);
    expect(activate().getAttribute('data-capability-enabled')).toBe('false');
    expect(posts(sent)).toHaveLength(0);
    expect(onChecked).not.toHaveBeenCalled();
  });

  it('shows a refused activation as a destructive toast', async () => {
    stubControlPlane(routes({ 'POST /api/v1/device/activate-json': refused(404, 'no matching profile') }));
    const onChecked = vi.fn();
    render(withControlPlane(<DeviceActivateCard serial="SN-1" onChecked={onChecked} />));

    await typeMacAndActivate();

    const toast = await screen.findByTestId('toast');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(toast.textContent).toContain('Activation check failed');
    expect(toast.textContent).toContain('no matching profile');
    expect(onChecked).not.toHaveBeenCalled();
  });
});
