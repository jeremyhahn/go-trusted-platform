import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { SDNPortStateCard } from './sdn-port-state-card';

// #2064: the SDN port state card sets a port's admin state and rate limits
// with SetPortState on `PUT /api/v1/sdn/bridges/{name}/ports/{port}/state`,
// asks before setting a port down, and shows a refusal verbatim.

const STATE = '/api/v1/sdn/bridges/br0/ports/p1/state';

const UP_PORT = ok({ port: { id: 'p1', bridgeId: 'br0', config: { name: 'veth-a' }, status: 'PORT_STATUS_UP' } });
const SET_OK = ok({ status: { success: true, message: 'ok' }, port: { id: 'p1', bridgeId: 'br0' } });

function routes(put?: Answer): Record<string, Answer> {
  return put ? { [`GET ${STATE}`]: UP_PORT, [`PUT ${STATE}`]: put } : { [`GET ${STATE}`]: UP_PORT };
}

function puts(sent: { method: string; path: string; body: unknown }[]) {
  return sent.filter((r) => r.method === 'PUT' && r.path === STATE);
}

async function renderCard() {
  render(withControlPlane(<SDNPortStateCard bridgeId="br0" portId="p1" />));
  await screen.findByTestId('sdn-port-status');
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

describe('SDNPortStateCard set', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('sets the port up with rates at once', async () => {
    const sent = stubControlPlane(routes(SET_OK));
    await renderCard();
    type('Ingress rate (bps)', '2000');
    type('Ingress burst (bits)', '1000');
    await click('Apply');
    expect(screen.queryByRole('dialog')).toBeNull();
    const toast = await screen.findByText('Port state set: Port p1 is up');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(puts(sent).map((r) => r.body)).toEqual([{ adminState: 'up', ingressRate: 2000, ingressBurst: 1000 }]);
    await waitFor(() => expect(sent.filter((r) => r.method === 'GET').length).toBe(2));
  });

  it('asks before setting the port down and sends nothing on Cancel', async () => {
    const sent = stubControlPlane(routes(SET_OK));
    await renderCard();
    type('Admin state', 'down');
    await click('Apply');
    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Set the port down?');
    await click('Cancel');
    expect(puts(sent)).toHaveLength(0);
  });

  it('sets the port down after the confirm', async () => {
    const sent = stubControlPlane(routes(SET_OK));
    await renderCard();
    type('Admin state', 'down');
    await click('Apply');
    await screen.findByRole('dialog');
    await click('Set down');
    const toast = await screen.findByText('Port state set: Port p1 is down');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(puts(sent).map((r) => r.body)).toEqual([{ adminState: 'down' }]);
  });

  it('shows the policing refusal verbatim', async () => {
    stubControlPlane(
      routes(
        refused(
          400,
          'ovs: invalid ingress policing: rate 1500 bps, burst 0 bits (each must be 0 or a whole multiple of 1000, and a burst needs a rate)'
        )
      )
    );
    await renderCard();
    type('Ingress rate (bps)', '1500');
    await click('Apply');
    const toast = await screen.findByText(/^Set port state failed: ovs: invalid ingress policing: rate 1500 bps/);
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect((screen.getByLabelText('Ingress rate (bps)') as HTMLInputElement).value).toBe('1500');
  });

  it('refuses a non-numeric rate without a request', async () => {
    const sent = stubControlPlane(routes(SET_OK));
    await renderCard();
    type('Egress rate (bps)', 'fast');
    await click('Apply');
    const toast = await screen.findByText('Invalid rate: rates are whole numbers of bits per second');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(puts(sent)).toHaveLength(0);
  });
});
