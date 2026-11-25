import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import { DeviceSerialCard } from './device-serial-card';

// #2048: the device page edits the device serial through the SDK updateDevice (PUT /devices/{id}), capability-gated; a serial another device holds is refused with 409.

const UPDATE_OP = 'PUT /api/v1/devices/{id:[0-9]+}';

// The server's capabilities listing for the device update op.
function caps(enabled = true): Answer {
  const capabilities = [
    enabled
      ? { op: UPDATE_OP, kind: 'route', enabled: true }
      : { op: UPDATE_OP, kind: 'route', enabled: false, reason: 'unimplemented' },
  ];
  return ok({ capabilities, total: 1, enabled: enabled ? 1 : 0 });
}

function routes(overrides: Record<string, Answer> = {}): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    'PUT /api/v1/devices/7': ok({ id: 7, serial: 'node-08', model: 'X10' }),
    ...overrides,
  };
}

const save = () => screen.getByRole('button', { name: 'Save serial' });

async function editAndSave(value: string) {
  fireEvent.change(await screen.findByLabelText('Serial'), { target: { value } });
  await waitFor(() => expect(save().hasAttribute('disabled')).toBe(false));
  await act(async () => {
    fireEvent.click(save());
  });
}

const puts = (sent: SentRequest[]) => sent.filter((r) => r.method === 'PUT');

describe('DeviceSerialCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('saves the serial through PUT /api/v1/devices/{id} and calls onSaved', async () => {
    const sent = stubControlPlane(routes());
    const onSaved = vi.fn();
    render(withControlPlane(<DeviceSerialCard deviceId="7" serial="node-07" onSaved={onSaved} />));

    await editAndSave('node-08');

    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
    const sentPuts = puts(sent);
    expect(sentPuts).toHaveLength(1);
    expect(sentPuts[0]).toEqual({
      method: 'PUT',
      path: '/api/v1/devices/7',
      body: { device: { id: '7', serial: 'node-08' } },
    });
    const toast = await screen.findByTestId('toast');
    expect(toast.getAttribute('data-variant')).not.toBe('destructive');
  });

  it('sends neither state nor model', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<DeviceSerialCard deviceId="7" serial="node-07" onSaved={vi.fn()} />));

    await editAndSave('node-08');

    await waitFor(() => expect(puts(sent)).toHaveLength(1));
    const body = puts(sent)[0].body as { device: Record<string, unknown> };
    expect('state' in body.device).toBe(false);
    expect('model' in body.device).toBe(false);
  });

  it('shows the 409 for a serial another device holds as a destructive toast', async () => {
    stubControlPlane(routes({ 'PUT /api/v1/devices/7': refused(409, 'device serial node-08 already exists') }));
    const onSaved = vi.fn();
    render(withControlPlane(<DeviceSerialCard deviceId="7" serial="node-07" onSaved={onSaved} />));

    await editAndSave('node-08');

    const toast = await screen.findByTestId('toast');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(toast.textContent).toContain('already exists');
    expect(onSaved).not.toHaveBeenCalled();
  });

  it('keeps Save serial disabled when the server does not offer the update', async () => {
    const sent = stubControlPlane(routes({ 'GET /api/v1/capabilities': caps(false) }));
    render(withControlPlane(<DeviceSerialCard deviceId="7" serial="node-07" onSaved={vi.fn()} />));

    fireEvent.change(await screen.findByLabelText('Serial'), { target: { value: 'node-08' } });
    await waitFor(() => expect(save().getAttribute('title')).toBe('unimplemented'));
    expect(save().hasAttribute('disabled')).toBe(true);
    expect(puts(sent)).toHaveLength(0);
  });

  it('carries the device-serial-save test id on its Save serial button', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<DeviceSerialCard deviceId="7" serial="node-07" onSaved={vi.fn()} />));

    await screen.findByLabelText('Serial');
    expect(screen.getByTestId('device-serial-save')).toBe(save());
  });
});
