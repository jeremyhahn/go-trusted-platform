import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { DeviceModelCard } from './device-model-card';

// #2048: the device page edits the device model through the SDK
// updateDevice (PUT /devices/{id}), capability-gated; state is never sent,
// Enable and Disable stay on the lifecycle transitions.

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
    'PUT /api/v1/devices/7': ok({ id: 7, serial: 'node-07', model: 'X11' }),
    ...overrides,
  };
}

const save = () => screen.getByRole('button', { name: 'Save' });

async function editAndSave(value: string) {
  fireEvent.change(await screen.findByLabelText('Model'), { target: { value } });
  await waitFor(() => expect(save().hasAttribute('disabled')).toBe(false));
  await act(async () => {
    fireEvent.click(save());
  });
}

const puts = (sent: { method: string }[]) => sent.filter((r) => r.method === 'PUT');

describe('DeviceModelCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('saves the model through PUT /api/v1/devices/{id} and calls onSaved', async () => {
    const sent = stubControlPlane(routes());
    const onSaved = vi.fn();
    render(withControlPlane(<DeviceModelCard deviceId="7" model="X10" onSaved={onSaved} />));

    await editAndSave('X11');

    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
    const sentPuts = puts(sent);
    expect(sentPuts).toHaveLength(1);
    expect(sentPuts[0]).toEqual({
      method: 'PUT',
      path: '/api/v1/devices/7',
      body: { device: { id: '7', model: 'X11' } },
    });
    const toast = await screen.findByTestId('toast');
    expect(toast.getAttribute('data-variant')).not.toBe('destructive');
  });

  it('never sends state in the PUT body', async () => {
    const sent = stubControlPlane(routes());
    const onSaved = vi.fn();
    render(withControlPlane(<DeviceModelCard deviceId="7" model="X10" onSaved={onSaved} />));

    await editAndSave('X11');

    await waitFor(() => expect(puts(sent)).toHaveLength(1));
    const body = puts(sent)[0].body as { device: Record<string, unknown> };
    expect('state' in body.device).toBe(false);
  });

  it('shows the server refusal as a destructive toast', async () => {
    stubControlPlane(routes({ 'PUT /api/v1/devices/7': refused(400, 'model too long') }));
    const onSaved = vi.fn();
    render(withControlPlane(<DeviceModelCard deviceId="7" model="X10" onSaved={onSaved} />));

    await editAndSave('X11');

    const toast = await screen.findByTestId('toast');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(toast.textContent).toContain('model too long');
    expect(onSaved).not.toHaveBeenCalled();
  });

  it('keeps Save disabled when the server does not offer the update', async () => {
    const sent = stubControlPlane(routes({ 'GET /api/v1/capabilities': caps(false) }));
    render(withControlPlane(<DeviceModelCard deviceId="7" model="X10" onSaved={vi.fn()} />));

    fireEvent.change(await screen.findByLabelText('Model'), { target: { value: 'X11' } });
    await waitFor(() => expect(save().getAttribute('title')).toBe('unimplemented'));
    expect(save().hasAttribute('disabled')).toBe(true);
    expect(puts(sent)).toHaveLength(0);
  });
});
