import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import type { VM } from '@/types/infrastructure';
import { VMTable } from './vm-table';

// Opening a Radix menu in jsdom is slow, so the row menu renders its items
// inline, as in device-table.test.tsx. The items' onClick are the table's own.
vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: ({ children, onClick }: { children: ReactNode; onClick?: () => void }) => (
    <div role="menuitem" onClick={onClick}>
      {children}
    </div>
  ),
}));

function vm(overrides: Partial<VM> = {}): VM {
  return {
    id: 'vm-1',
    name: 'build',
    status: 'running',
    vcpus: 4,
    memoryMB: 4096,
    storageMB: 20480,
    ipAddress: 'ip-of-build',
    createdAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
    ...overrides,
  };
}

function mount(vms: VM[], onConsole?: (v: VM) => void) {
  const onRefresh = vi.fn();
  render(withControlPlane(<VMTable vms={vms} onRefresh={onRefresh} onConsole={onConsole} />));
  return { onRefresh };
}

async function choose(item: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('menuitem', { name: item }));
  });
}

describe('VMTable', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the empty row without VMs', () => {
    stubControlPlane({});
    mount([]);

    expect(screen.getByText('No virtual machines found')).toBeDefined();
    expect(screen.queryByRole('menu')).toBeNull();
  });

  it('renders a row per VM with sizes in GB from 1024 MB, its address and age', () => {
    stubControlPlane({});
    mount([vm(), vm({ id: 'vm-2', name: 'tiny', status: 'stopped', vcpus: 1, memoryMB: 512, storageMB: 1023, ipAddress: undefined })]);

    const rows = screen.getAllByRole('row');
    expect(rows).toHaveLength(3);
    const build = within(rows[1]);
    expect(build.getByText('build')).toBeDefined();
    expect(build.getByText('running').className).toContain('text-green-500');
    expect(build.getByText('4')).toBeDefined();
    expect(build.getByText('4.0 GB')).toBeDefined();
    expect(build.getByText('20.0 GB')).toBeDefined();
    expect(build.getByText('ip-of-build')).toBeDefined();
    expect(build.getByText('3 days ago')).toBeDefined();
    const tiny = within(rows[2]);
    expect(tiny.getByText('512 MB')).toBeDefined();
    expect(tiny.getByText('1023 MB')).toBeDefined();
    expect(tiny.getByText('-')).toBeDefined();
  });

  it('shows exactly 1024 MB as 1.0 GB', () => {
    stubControlPlane({});
    mount([vm({ memoryMB: 1024, storageMB: 1536 })]);

    expect(screen.getByText('1.0 GB')).toBeDefined();
    expect(screen.getByText('1.5 GB')).toBeDefined();
  });

  it('gives each status its colour', () => {
    stubControlPlane({});
    mount([
      vm({ id: '1', status: 'stopped' }),
      vm({ id: '2', status: 'suspended' }),
      vm({ id: '3', status: 'creating' }),
    ]);

    expect(screen.getByText('stopped').className).toContain('text-gray-500');
    expect(screen.getByText('suspended').className).toContain('text-yellow-500');
    expect(screen.getByText('creating').className).toContain('text-blue-500');
  });

  it('offers Stop, Reboot and Console for a running VM, not Start', () => {
    stubControlPlane({});
    const onConsole = vi.fn();
    const v = vm();
    mount([v], onConsole);

    expect(screen.queryByRole('menuitem', { name: 'Start' })).toBeNull();
    expect(screen.getByRole('menuitem', { name: 'Stop' })).toBeDefined();
    expect(screen.getByRole('menuitem', { name: 'Reboot' })).toBeDefined();
    fireEvent.click(screen.getByRole('menuitem', { name: 'Console' }));
    expect(onConsole).toHaveBeenCalledWith(v);
  });

  it('hides Console without its handler', () => {
    stubControlPlane({});
    mount([vm()]);

    expect(screen.queryByRole('menuitem', { name: 'Console' })).toBeNull();
  });

  it('offers Start and Delete only for a suspended VM', () => {
    stubControlPlane({});
    mount([vm({ status: 'suspended' })], vi.fn());

    expect(screen.getAllByRole('menuitem').map((m) => m.textContent)).toEqual(['Start', 'Delete']);
  });

  it.each([
    ['Start', 'stopped', 'POST /api/v1/compute/vms/vm-1/start', 'VM started successfully'],
    ['Stop', 'running', 'POST /api/v1/compute/vms/vm-1/stop', 'VM stopped successfully'],
    ['Reboot', 'running', 'POST /api/v1/compute/vms/vm-1/reboot', 'VM rebooted successfully'],
    ['Delete', 'running', 'DELETE /api/v1/compute/vms/vm-1', 'VM deleted successfully'],
  ] as const)('%s sends %s %s and refreshes', async (item, status, route, message) => {
    const sent = stubControlPlane({ [route]: ok({}) });
    const { onRefresh } = mount([vm({ status })]);

    await choose(item);

    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
    expect(sent.map((r) => `${r.method} ${r.path}`)).toEqual([route]);
    expect(screen.getByText(`Success: ${message}`)).toBeDefined();
    expect((screen.getAllByRole('button')[0] as HTMLButtonElement).disabled).toBe(false);
  });

  it.each([
    ['Start', 'stopped', 'POST /api/v1/compute/vms/vm-1/start', 'Failed to start VM: host offline'],
    ['Stop', 'running', 'POST /api/v1/compute/vms/vm-1/stop', 'Failed to stop VM: host offline'],
    ['Reboot', 'running', 'POST /api/v1/compute/vms/vm-1/reboot', 'Failed to reboot VM: host offline'],
    ['Delete', 'running', 'DELETE /api/v1/compute/vms/vm-1', 'Failed to delete VM: host offline'],
  ] as const)('shows a refused %s as a destructive toast and does not refresh', async (item, status, route, message) => {
    stubControlPlane({ [route]: refused(503, 'host offline') });
    const { onRefresh } = mount([vm({ status })]);

    await choose(item);

    const toast = await screen.findByText(`Error: ${message}`);
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(onRefresh).not.toHaveBeenCalled();
    expect((screen.getAllByRole('button')[0] as HTMLButtonElement).disabled).toBe(false);
  });
});
