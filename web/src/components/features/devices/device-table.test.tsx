import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import type { Device } from '@/types/device';
import { DeviceTable } from './device-table';

// #250: the table's Enable / Disable Device item sends the control plane's
// lifecycle transition, and a refusal reaches the operator as a destructive
// toast. Before it, the item was disabled (#229), and before that it called
// a mutation that sent nothing and toasted success.

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

// Opening a Radix menu in jsdom costs tens of seconds, so the row menu
// renders its items inline. The item's onClick and disabled state are the
// table's own; only the popup machinery is replaced.
vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: ({
    children,
    disabled,
    title,
    onClick,
  }: {
    children: ReactNode;
    disabled?: boolean;
    title?: string;
    onClick?: () => void;
  }) => (
    <div role="menuitem" aria-disabled={disabled} title={title} onClick={disabled ? undefined : onClick}>
      {children}
    </div>
  ),
}));

function device(overrides: Partial<Device> = {}): Device {
  return {
    id: '7',
    name: 'node-07',
    type: 'physical',
    status: 'online',
    state: 'attested',
    registeredAt: '2026-10-01T00:00:00Z',
    ...overrides,
  };
}

async function choose(item: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('menuitem', { name: item }));
  });
}

describe('DeviceTable Enable / Disable Device', () => {
  beforeEach(() => {
    vi.stubGlobal('confirm', vi.fn(() => true));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('disables through POST /devices/{id}/disable and re-reads the fleet', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/devices/7/disable': ok({
        device_id: '7',
        state: 'suspended',
        previous_state: 'attested',
        reattestation_requested: false,
      }),
    });
    const onDeviceChange = vi.fn();
    render(withControlPlane(<DeviceTable devices={[device()]} onDeviceChange={onDeviceChange} />));

    await choose('Disable Device');

    await waitFor(() => expect(onDeviceChange).toHaveBeenCalledTimes(1));
    expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/devices/7/disable', body: {} });
    expect(sent.some((r) => r.method === 'PUT')).toBe(false);
    expect(screen.getByText('Device disabled: Device disabled: its switch port is blocked.')).toBeDefined();
  });

  it('shows the control plane refusal as a destructive toast', async () => {
    stubControlPlane({
      'POST /api/v1/devices/7/disable': refused(400, 'device 7 has no network port on record'),
    });
    const onDeviceChange = vi.fn();
    render(withControlPlane(<DeviceTable devices={[device()]} onDeviceChange={onDeviceChange} />));

    await choose('Disable Device');

    const toast = await screen.findByText('Disable refused: device 7 has no network port on record');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(onDeviceChange).not.toHaveBeenCalled();
  });

  it('sends nothing when the operator cancels the disable', async () => {
    vi.stubGlobal('confirm', vi.fn(() => false));
    const sent = stubControlPlane({});
    render(withControlPlane(<DeviceTable devices={[device()]} />));

    await choose('Disable Device');

    expect(sent.filter((r) => r.method === 'POST')).toEqual([]);
  });

  it('offers Enable for a suspended device, whose badge reads Disabled', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/devices/7/enable': ok({
        device_id: '7',
        state: 'quarantined',
        previous_state: 'suspended',
        reattestation_requested: true,
      }),
    });
    render(withControlPlane(<DeviceTable devices={[device({ state: 'suspended', status: 'disabled' })]} />));

    expect(screen.getByText('Disabled')).toBeDefined();

    await choose('Enable Device');

    await waitFor(() =>
      expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/devices/7/enable', body: {} })
    );
    expect(vi.mocked(confirm)).not.toHaveBeenCalled();
    expect(await screen.findByText(/^Device enabled: Device re-admitted to quarantine/)).toBeDefined();
  });

  it('offers no transition for a revoked device', () => {
    stubControlPlane({});
    render(withControlPlane(<DeviceTable devices={[device({ state: 'revoked', status: 'disabled' })]} />));

    const item = screen.getByRole('menuitem', { name: 'Disable Device' });
    expect(item.getAttribute('aria-disabled')).toBe('true');
    expect(item.getAttribute('title')).toMatch(/revocation is terminal/);
    expect(screen.queryByRole('menuitem', { name: 'Enable Device' })).toBeNull();
  });
});
