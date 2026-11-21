import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { SDNPortStateCard, parseRate, portStatusLabel } from './sdn-port-state-card';

// #2064: the SDN port state card reads a port's state with GetPort on
// `GET /api/v1/sdn/bridges/{name}/ports/{port}/state` through the real SDK
// client, and shows a refusal verbatim.

const STATE = '/api/v1/sdn/bridges/br0/ports/p1/state';

function storedPort(status: string): Answer {
  return ok({ port: { id: 'p1', bridgeId: 'br0', config: { name: 'veth-a' }, status } });
}

function gets(sent: { method: string; path: string }[]): number {
  return sent.filter((r) => r.method === 'GET' && r.path === STATE).length;
}

function renderCard() {
  render(withControlPlane(<SDNPortStateCard bridgeId="br0" portId="p1" />));
}

describe('SDNPortStateCard read', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads the port on mount', async () => {
    const sent = stubControlPlane({ [`GET ${STATE}`]: storedPort('PORT_STATUS_UP') });
    renderCard();
    await waitFor(() => {
      expect(screen.getByTestId('sdn-port-name').textContent).toBe('veth-a');
      expect(screen.getByTestId('sdn-port-status').textContent).toBe('UP');
    });
    expect(gets(sent)).toBe(1);
  });

  it('shows a down port', async () => {
    stubControlPlane({ [`GET ${STATE}`]: storedPort('PORT_STATUS_DOWN') });
    renderCard();
    await waitFor(() => {
      expect(screen.getByTestId('sdn-port-status').textContent).toBe('DOWN');
    });
  });

  it('re-reads on Refresh', async () => {
    const sent = stubControlPlane({ [`GET ${STATE}`]: storedPort('PORT_STATUS_UP') });
    renderCard();
    await screen.findByTestId('sdn-port-status');
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    });
    await waitFor(() => expect(gets(sent)).toBe(2));
  });

  it('shows an unknown port', async () => {
    stubControlPlane({ [`GET ${STATE}`]: refused(404, 'port not found') });
    renderCard();
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('port not found');
    expect(screen.queryByTestId('sdn-port-status')).toBeNull();
  });

  it('labels the status', () => {
    expect(portStatusLabel('PORT_STATUS_BLOCKED')).toBe('BLOCKED');
    expect(portStatusLabel(undefined)).toBe('UNKNOWN');
    expect(portStatusLabel('')).toBe('UNKNOWN');
    expect(parseRate(' ')).toBeUndefined();
    expect(parseRate('2000')).toBe(2000);
    expect(Number.isNaN(parseRate('-1'))).toBe(true);
    expect(Number.isNaN(parseRate('ten'))).toBe(true);
  });
});
