import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { SwitchPortStatus } from 'trusted-platform-sdk';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import SwitchesPage from './page';

// #2066: the switches page takes a switch name and drives ListPorts,
// GetPortStatus, EnablePort, DisablePort and SetPortVLAN through the SDK,
// every control gated on its switch route.

const SWITCH_OPS = [
  'GET /api/v1/switches/{switch}/ports',
  'GET /api/v1/switches/{switch}/ports/{port}',
  'POST /api/v1/switches/{switch}/ports/{port}/enable',
  'POST /api/v1/switches/{switch}/ports/{port}/disable',
  'POST /api/v1/switches/{switch}/ports/{port}/vlan',
] as const;

const PORT_READ = 'GET /api/v1/switches/{switch}/ports/{port}';

// The server's capabilities listing: every switch op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = SWITCH_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: switch' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

const PORTS: SwitchPortStatus[] = [
  { port: 'Eth1/1', mode: 'access', access_vlan: 10, enabled: true, link_up: true },
  { port: 'Eth1/5', mode: 'trunk', access_vlan: 0, trunk_vlans: [10, 20], native_vlan: 1, enabled: false, link_up: false },
];

const LIST = '/api/v1/switches/core-1/ports';
const CAPS_PATH = '/api/v1/capabilities';

function setup(routes: Record<string, Answer>, off: string[] = []) {
  const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps(off), ...routes });
  render(withControlPlane(<SwitchesPage />));
  return sent;
}

function showSwitch(name = 'core-1') {
  fireEvent.change(screen.getByLabelText('Switch name'), { target: { value: name } });
  fireEvent.click(screen.getByRole('button', { name: 'Show ports' }));
}

function row(port: string) {
  return within(screen.getByTestId(`switch-port-${port}`));
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('SwitchesPage', () => {
  it('sends nothing until a switch is named', async () => {
    const sent = setup({ [`GET ${LIST}`]: ok(PORTS) });
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(sent.filter((r) => r.path !== CAPS_PATH)).toEqual([]);
    expect((screen.getByRole('button', { name: 'Show ports' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("lists the named switch's ports through the SDK", async () => {
    const sent = setup({ [`GET ${LIST}`]: ok(PORTS) });
    showSwitch();
    expect(await screen.findByTestId('switch-port-Eth1/1')).toBeTruthy();
    expect(screen.getByTestId('switch-port-Eth1/5')).toBeTruthy();
    expect(sent.some((r) => r.method === 'GET' && r.path === LIST)).toBe(true);
  });

  it('shows a refused list as an alert', async () => {
    setup({ [`GET ${LIST}`]: refused(404, 'switch not found') });
    showSwitch();
    await waitFor(() => {
      expect(screen.getAllByRole('alert').some((a) => (a.textContent ?? '').includes('switch not found'))).toBe(true);
    });
    expect(screen.queryByTestId('switch-port-Eth1/1')).toBeNull();
  });

  it('disables a port and re-reads the ports', async () => {
    const sent = setup({
      [`GET ${LIST}`]: ok(PORTS),
      [`POST ${LIST}/Eth1%2F1/disable`]: ok({ switch: 'core-1', port: 'Eth1/1', status: 'ok' }),
    });
    showSwitch();
    await screen.findByTestId('switch-port-Eth1/1');
    const button = row('Eth1/1').getByRole('button', { name: 'Disable' });
    await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('true'));
    fireEvent.click(button);
    await waitFor(() => {
      const post = sent.findIndex((r) => r.method === 'POST' && r.path === `${LIST}/Eth1%2F1/disable`);
      expect(post).toBeGreaterThanOrEqual(0);
      expect(sent[post].body).toEqual({});
      expect(sent.slice(post + 1).some((r) => r.method === 'GET' && r.path === LIST)).toBe(true);
    });
  });

  it("reads one port's status", async () => {
    const sent = setup({
      [`GET ${LIST}`]: ok(PORTS),
      [`GET ${LIST}/Eth1%2F5`]: ok(PORTS[1]),
    });
    showSwitch();
    await screen.findByTestId('switch-port-Eth1/5');
    fireEvent.change(screen.getByLabelText('Port'), { target: { value: 'Eth1/5' } });
    const button = screen.getByRole('button', { name: 'Read port status' });
    await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('true'));
    fireEvent.click(button);
    const card = within(await screen.findByTestId('switch-port-status'));
    expect(card.getByText(/trunk/)).toBeTruthy();
    expect(card.getByText(/Disabled/)).toBeTruthy();
    expect(card.getByText(/Down/)).toBeTruthy();
    expect(sent.some((r) => r.method === 'GET' && r.path === `${LIST}/Eth1%2F5`)).toBe(true);
  });

  it('withholds the port read the server does not offer', async () => {
    const sent = setup({ [`GET ${LIST}`]: ok(PORTS), [`GET ${LIST}/Eth1%2F5`]: ok(PORTS[1]) }, [PORT_READ]);
    showSwitch();
    await screen.findByTestId('switch-port-Eth1/5');
    fireEvent.change(screen.getByLabelText('Port'), { target: { value: 'Eth1/5' } });
    const button = screen.getByRole('button', { name: 'Read port status' });
    await waitFor(() => expect(button.getAttribute('title')).toBe('not-configured: switch'));
    expect(button.getAttribute('data-capability-enabled')).toBe('false');
    fireEvent.click(button);
    await act(async () => {
      await new Promise((r) => setTimeout(r, 20));
    });
    expect(sent.some((r) => r.path === `${LIST}/Eth1%2F5`)).toBe(false);
  });
});
