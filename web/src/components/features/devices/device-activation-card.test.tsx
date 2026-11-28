import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { DeviceActivationCard } from './device-activation-card';

// #2048: the activation card finds a registered device by serial on the
// served GET /devices/serial/{serial} route, through the real SDK API client.

const FIND_PATH = 'GET /api/v1/devices/serial/SN-1';

const baseDevice: Answer = ok({
  id: '7',
  serial: 'SN-1',
  model: 'rpi4',
  state: 'enrolled',
  switch_name: 'sw1',
  switch_port: 'ge-0/0/3',
});

function typeSerial(value: string) {
  fireEvent.change(screen.getByLabelText('Serial number'), { target: { value } });
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

describe('DeviceActivationCard find by serial', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('finds a device by serial', async () => {
    const sent = stubControlPlane({ [FIND_PATH]: baseDevice });
    render(withControlPlane(<DeviceActivationCard />));

    typeSerial('SN-1');
    await click('Find');

    const found = await screen.findByTestId('device-activation-found');
    expect(sent.filter((r) => r.method === 'GET')).toHaveLength(1);
    for (const text of ['7', 'SN-1', 'rpi4', 'enrolled', 'ge-0/0/3']) {
      expect(found.textContent).toContain(text);
    }
  });

  it('trims the serial', async () => {
    const sent = stubControlPlane({ [FIND_PATH]: baseDevice });
    render(withControlPlane(<DeviceActivationCard />));

    typeSerial(' SN-1 ');
    await click('Find');

    await screen.findByTestId('device-activation-found');
    expect(sent.map((r) => r.path)).toEqual(['/api/v1/devices/serial/SN-1']);
  });

  it('shows a not-found refusal verbatim', async () => {
    stubControlPlane({ [FIND_PATH]: refused(404, 'device not found: SN-1') });
    render(withControlPlane(<DeviceActivationCard />));

    typeSerial('SN-1');
    await click('Find');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('device not found: SN-1');
    expect(screen.queryByTestId('device-activation-found')).toBeNull();
  });

  it('refuses a blank serial without a request', async () => {
    const sent = stubControlPlane({ [FIND_PATH]: baseDevice });
    render(withControlPlane(<DeviceActivationCard />));

    await click('Find');

    const toast = await screen.findByText('Serial number required: enter the device serial');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(sent).toHaveLength(0);
  });
});
