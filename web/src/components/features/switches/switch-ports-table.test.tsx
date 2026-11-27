import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { SwitchPortStatus } from 'trusted-platform-sdk';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { SwitchPortsTable } from './switch-ports-table';

// #2066: the switch ports table offers Enable, Disable and Set VLAN per
// port, each gated on its switch route, and reports refusals as toasts.

const SWITCH_OPS = [
  'POST /api/v1/switches/{switch}/ports/{port}/enable',
  'POST /api/v1/switches/{switch}/ports/{port}/disable',
  'POST /api/v1/switches/{switch}/ports/{port}/vlan',
] as const;

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

function setup(off: string[] = []) {
  stubControlPlane({ 'GET /api/v1/capabilities': caps(off) });
  const onEnable = vi.fn().mockResolvedValue(undefined);
  const onDisable = vi.fn().mockResolvedValue(undefined);
  const onSetVLAN = vi.fn().mockResolvedValue(undefined);
  render(
    withControlPlane(
      <SwitchPortsTable switchName="core-1" ports={PORTS} onEnable={onEnable} onDisable={onDisable} onSetVLAN={onSetVLAN} />,
    ),
  );
  return { onEnable, onDisable, onSetVLAN };
}

function row(port: string) {
  return within(screen.getByTestId(`switch-port-${port}`));
}

// Waits until the capabilities listing has reached the gate on the button.
async function enabledButton(port: string, name: string) {
  const button = row(port).getByRole('button', { name });
  await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('true'));
  return button;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('SwitchPortsTable', () => {
  it('lists each port with its mode, VLAN and state', () => {
    setup();
    expect(screen.getByText('Ports on core-1')).toBeTruthy();
    const access = row('Eth1/1');
    expect(access.getByText('access')).toBeTruthy();
    expect(access.getByText('10')).toBeTruthy();
    expect(access.getByText('Enabled')).toBeTruthy();
    expect(access.getByText('Up')).toBeTruthy();
    const trunk = row('Eth1/5');
    expect(trunk.getByText('trunk')).toBeTruthy();
    expect(trunk.getByText(/10, 20/)).toBeTruthy();
    expect(trunk.getByText(/native 1/)).toBeTruthy();
    expect(trunk.getByText('Disabled')).toBeTruthy();
    expect(trunk.getByText('Down')).toBeTruthy();
  });

  it('disables an enabled port and enables a disabled one', async () => {
    const { onEnable, onDisable } = setup();
    expect(row('Eth1/1').queryByRole('button', { name: 'Enable' })).toBeNull();
    expect(row('Eth1/5').queryByRole('button', { name: 'Disable' })).toBeNull();

    fireEvent.click(await enabledButton('Eth1/1', 'Disable'));
    await waitFor(() => expect(onDisable).toHaveBeenCalledWith('Eth1/1'));

    fireEvent.click(await enabledButton('Eth1/5', 'Enable'));
    await waitFor(() => expect(onEnable).toHaveBeenCalledWith('Eth1/5'));
  });

  it('sets a VLAN from the row field', async () => {
    const { onSetVLAN } = setup();
    fireEvent.change(screen.getByLabelText('VLAN for Eth1/1'), { target: { value: '20' } });
    fireEvent.click(await enabledButton('Eth1/1', 'Set VLAN'));
    await waitFor(() => expect(onSetVLAN).toHaveBeenCalledWith('Eth1/1', 20));
  });

  it('refuses a VLAN outside 1-4094 without calling the handler', async () => {
    const { onSetVLAN } = setup();
    fireEvent.change(screen.getByLabelText('VLAN for Eth1/1'), { target: { value: '4095' } });
    fireEvent.click(await enabledButton('Eth1/1', 'Set VLAN'));
    expect(await row('Eth1/1').findByText('VLAN must be 1-4094')).toBeTruthy();
    expect(onSetVLAN).not.toHaveBeenCalled();
  });

  it('shows a rejected handler as a destructive toast', async () => {
    const { onSetVLAN } = setup();
    onSetVLAN.mockRejectedValue(new Error('port is a trunk'));
    fireEvent.change(screen.getByLabelText('VLAN for Eth1/1'), { target: { value: '30' } });
    fireEvent.click(await enabledButton('Eth1/1', 'Set VLAN'));
    await waitFor(() => {
      expect(screen.getAllByTestId('toast').some((t) => (t.textContent ?? '').includes('port is a trunk'))).toBe(true);
    });
  });

  it('withholds the controls the server does not offer', async () => {
    const { onEnable, onDisable, onSetVLAN } = setup([...SWITCH_OPS]);
    const buttons = [
      row('Eth1/1').getByRole('button', { name: 'Disable' }),
      row('Eth1/5').getByRole('button', { name: 'Enable' }),
      ...screen.getAllByRole('button', { name: 'Set VLAN' }),
    ];
    await waitFor(() => {
      for (const b of buttons) {
        expect(b.getAttribute('title')).toBe('not-configured: switch');
      }
    });
    for (const b of buttons) {
      expect((b as HTMLButtonElement).disabled).toBe(true);
      expect(b.getAttribute('data-capability-enabled')).toBe('false');
    }
    fireEvent.change(screen.getByLabelText('VLAN for Eth1/1'), { target: { value: '20' } });
    for (const b of buttons) fireEvent.click(b);
    expect(onEnable).not.toHaveBeenCalled();
    expect(onDisable).not.toHaveBeenCalled();
    expect(onSetVLAN).not.toHaveBeenCalled();
  });
});
