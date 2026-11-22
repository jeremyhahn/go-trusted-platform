import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import type { VTPM } from '@/types/device';
import { VTPMTable } from './vtpm-table';

const push = vi.fn();
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, back: vi.fn() }),
}));

// Radix menus do not open in jsdom; render every item inline instead.
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

function vtpm(over: Partial<VTPM> = {}): VTPM {
  return {
    id: 'v1',
    name: 'vtpm-one',
    vmId: 'vm-1',
    vmName: 'vm-one',
    state: 'active',
    pcrProfile: 'default',
    createdAt: '2026-01-15T12:00:00Z',
    ...over,
  };
}

function items(): string[] {
  return screen.getAllByRole('menuitem').map((item) => item.textContent ?? '');
}

async function choose(item: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('menuitem', { name: item }));
  });
}

describe('VTPMTable', () => {
  beforeEach(() => {
    push.mockReset();
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the empty state without rows', () => {
    stubControlPlane({});
    render(withControlPlane(<VTPMTable vtpms={[]} />));

    expect(screen.getByText('No vTPM instances found')).toBeDefined();
    expect(screen.queryByRole('menuitem')).toBeNull();
  });

  it('renders name, VM, PCR profile and creation date in the row', () => {
    stubControlPlane({});
    render(withControlPlane(<VTPMTable vtpms={[vtpm()]} />));

    const row = screen.getByText('vtpm-one').closest('tr') as HTMLElement;
    expect(within(row).getByText('vm-one')).toBeDefined();
    expect(within(row).getByText('vm-1')).toBeDefined();
    expect(within(row).getByText('default')).toBeDefined();
    expect(within(row).getByText(/Jan 1[56], 2026/)).toBeDefined();
  });

  it.each([
    ['active', 'Active'],
    ['sealed', 'Sealed'],
    ['migrating', 'Migrating'],
    ['suspended', 'Suspended'],
  ] as const)('labels the %s state as %s', (state, label) => {
    stubControlPlane({});
    render(withControlPlane(<VTPMTable vtpms={[vtpm({ state })]} />));
    expect(screen.getByText(label)).toBeDefined();
  });

  it.each([
    ['active', ['View Details', 'Seal Data', 'Suspend', 'Migrate', 'Delete']],
    ['suspended', ['View Details', 'Resume', 'Migrate', 'Delete']],
    ['sealed', ['View Details', 'Migrate', 'Delete']],
    ['migrating', ['View Details', 'Delete']],
  ] as const)('offers the %s state only its actions', (state, expected) => {
    stubControlPlane({});
    render(withControlPlane(<VTPMTable vtpms={[vtpm({ state })]} />));
    expect(items()).toEqual(expected);
  });

  it('navigates to details, seal and migrate for the vTPM', () => {
    stubControlPlane({});
    render(withControlPlane(<VTPMTable vtpms={[vtpm()]} />));

    fireEvent.click(screen.getByRole('menuitem', { name: 'View Details' }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Seal Data' }));
    fireEvent.click(screen.getByRole('menuitem', { name: 'Migrate' }));
    expect(push.mock.calls.map((call) => call[0])).toEqual([
      '/devices/vtpm/v1',
      '/devices/vtpm/v1?action=seal',
      '/devices/vtpm/v1?action=migrate',
    ]);
  });

  it('says suspend and resume are not implemented, and sends nothing', async () => {
    const sent = stubControlPlane({});
    render(withControlPlane(<VTPMTable vtpms={[vtpm(), vtpm({ id: 'v2', name: 'vtpm-two', state: 'suspended' })]} />));

    await choose('Suspend');
    expect(await screen.findByText('Info: Suspend operation not yet implemented in SDK')).toBeDefined();
    await choose('Resume');
    expect(await screen.findByText('Info: Resume operation not yet implemented in SDK')).toBeDefined();
    expect(sent).toEqual([]);
  });

  it('deletes only after the operator confirms, and reports the change', async () => {
    const sent = stubControlPlane({ 'DELETE /api/v1/vtpm/bundles/v1': ok({}) });
    const confirm = vi.fn(() => false);
    vi.stubGlobal('confirm', confirm);
    const onChange = vi.fn();
    render(withControlPlane(<VTPMTable vtpms={[vtpm()]} onVTPMChange={onChange} />));

    await choose('Delete');
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining('vtpm-one'));
    expect(sent).toEqual([]);

    confirm.mockReturnValue(true);
    await choose('Delete');

    expect(await screen.findByText('Success: vTPM deleted successfully')).toBeDefined();
    expect(sent.map((r) => `${r.method} ${r.path}`)).toEqual(['DELETE /api/v1/vtpm/bundles/v1']);
    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it('encodes an id carrying a slash into one path segment', async () => {
    const sent = stubControlPlane({ 'DELETE /api/v1/vtpm/bundles/a%2Fb': ok({}) });
    vi.stubGlobal('confirm', () => true);
    render(withControlPlane(<VTPMTable vtpms={[vtpm({ id: 'a/b' })]} />));

    await choose('Delete');

    await waitFor(() => expect(sent.map((r) => r.path)).toEqual(['/api/v1/vtpm/bundles/a%2Fb']));
  });

  it('shows a refused delete with its REST reason and re-enables the row', async () => {
    stubControlPlane({ 'DELETE /api/v1/vtpm/bundles/v1': refused(409, 'vTPM v1 is in use') });
    vi.stubGlobal('confirm', () => true);
    const onChange = vi.fn();
    render(withControlPlane(<VTPMTable vtpms={[vtpm()]} onVTPMChange={onChange} />));

    await choose('Delete');

    const toast = await screen.findByText('Error: vTPM v1 is in use');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(onChange).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Open menu' }).hasAttribute('disabled')).toBe(false));
  });
});
