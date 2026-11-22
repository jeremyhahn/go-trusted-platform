import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import { DeviceActivationCard } from './device-activation-card';

// #2048: the activation card activates a found device on the served
// POST /device/activate-json route only after the operator confirms.

const FIND_PATH = 'GET /api/v1/devices/serial/SN-1';
const ACTIVATE_PATH = 'POST /api/v1/device/activate-json';

const baseDevice: Answer = ok({
  id: '7',
  serial: 'SN-1',
  model: 'rpi4',
  state: 'enrolled',
  switch_name: 'sw1',
  switch_port: 'ge-0/0/3',
});

const activated: Answer = ok({ status: 'activated', vlan: 120, transitioned_at: '2026-11-21T00:00:00Z' });

async function renderFound(routes: Record<string, Answer>) {
  const sent = stubControlPlane({ [FIND_PATH]: baseDevice, ...routes });
  render(withControlPlane(<DeviceActivationCard />));
  fireEvent.change(screen.getByLabelText('Serial number'), { target: { value: 'SN-1' } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Find' }));
  });
  await screen.findByTestId('device-activation-found');
  return sent;
}

async function openConfirm() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Activate' }));
  });
  return screen.findByRole('dialog');
}

async function clickIn(dialog: HTMLElement, name: string) {
  await act(async () => {
    fireEvent.click(within(dialog).getByRole('button', { name }));
  });
}

function posts(sent: SentRequest[]) {
  return sent.filter((r) => r.method === 'POST');
}

describe('DeviceActivationCard activate', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('activates after the confirm', async () => {
    const sent = await renderFound({ [ACTIVATE_PATH]: activated });

    const dialog = await openConfirm();
    expect(dialog.textContent).toContain('Activate SN-1?');
    expect(posts(sent)).toHaveLength(0);

    await clickIn(dialog, 'Activate');

    const result = await screen.findByTestId('device-activation-result');
    expect(result.textContent).toContain('activated on VLAN 120');
    expect(posts(sent).map((r) => r.body)).toEqual([{ serial: 'SN-1' }]);
    const toast = await screen.findByText('Device activated: VLAN 120');
    expect(toast.getAttribute('data-variant')).toBe('success');
  });

  it('sends the MAC when given', async () => {
    const sent = await renderFound({ [ACTIVATE_PATH]: activated });

    fireEvent.change(screen.getByLabelText('MAC address (optional)'), { target: { value: 'aa:bb:cc:dd:ee:ff' } });
    const dialog = await openConfirm();
    await clickIn(dialog, 'Activate');

    await screen.findByTestId('device-activation-result');
    expect(posts(sent).map((r) => r.body)).toEqual([
      { serial: 'SN-1', mac_address: 'aa:bb:cc:dd:ee:ff' },
    ]);
  });

  it('sends nothing on Cancel', async () => {
    const sent = await renderFound({ [ACTIVATE_PATH]: activated });

    const dialog = await openConfirm();
    await clickIn(dialog, 'Cancel');

    expect(screen.queryByRole('dialog')).toBeNull();
    expect(posts(sent)).toHaveLength(0);
  });

  it('shows an activation refusal verbatim', async () => {
    await renderFound({ [ACTIVATE_PATH]: refused(404, 'no matching profile found') });

    const dialog = await openConfirm();
    await clickIn(dialog, 'Activate');

    const toast = await screen.findByText('Activation failed: no matching profile found');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByTestId('device-activation-result')).toBeNull();
  });
});
