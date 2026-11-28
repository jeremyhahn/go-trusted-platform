import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { SDNPortStateCard, parseRate, portStatusLabel } from './sdn-port-state-card';

const { off } = vi.hoisted(() => ({ off: new Set<string>() }));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) => (off.has(op) ? { enabled: false, reason: 'not-configured: sdn' } : { enabled: true }),
  }),
}));

const SET_OP = 'PUT /api/v1/sdn/bridges/{name}/ports/{port}/state';
const GET_OP = 'GET /api/v1/sdn/bridges/{name}/ports/{port}/state';

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
    off.clear();
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

describe('SDNPortStateCard capability gate (#2064)', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    off.clear();
  });

  it("withholds Apply with the server's reason when PUT .../state is not offered", async () => {
    off.add(SET_OP);
    const sent = stubControlPlane({ [`GET ${STATE}`]: storedPort('PORT_STATUS_UP') });
    renderCard();
    await screen.findByTestId('sdn-port-status');
    const apply = screen.getByRole('button', { name: 'Apply' }) as HTMLButtonElement;
    expect(apply.disabled).toBe(true);
    expect(apply.getAttribute('title')).toBe('not-configured: sdn');
    expect(apply.getAttribute('data-capability-op')).toBe(SET_OP);
    expect(apply.getAttribute('data-capability-enabled')).toBe('false');
    await act(async () => {
      fireEvent.click(apply);
    });
    expect(sent.filter((r) => r.method === 'PUT')).toHaveLength(0);
  });

  it('withholds Refresh when GET .../state is not offered', async () => {
    off.add(GET_OP);
    const sent = stubControlPlane({ [`GET ${STATE}`]: storedPort('PORT_STATUS_UP') });
    renderCard();
    await screen.findByTestId('sdn-port-status');
    const refresh = screen.getByRole('button', { name: 'Refresh' }) as HTMLButtonElement;
    expect(refresh.disabled).toBe(true);
    expect(refresh.getAttribute('data-capability-op')).toBe(GET_OP);
    await act(async () => {
      fireEvent.click(refresh);
    });
    expect(gets(sent)).toBe(1);
  });

  it('leaves Apply and Refresh enabled when the server offers them', async () => {
    stubControlPlane({ [`GET ${STATE}`]: storedPort('PORT_STATUS_UP') });
    renderCard();
    await screen.findByTestId('sdn-port-status');
    for (const name of ['Apply', 'Refresh']) {
      const button = screen.getByRole('button', { name }) as HTMLButtonElement;
      expect(button.getAttribute('data-capability-enabled')).toBe('true');
      expect(button.disabled).toBe(false);
    }
  });
});
