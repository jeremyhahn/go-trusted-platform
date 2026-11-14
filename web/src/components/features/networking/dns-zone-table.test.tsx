import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { useState, type ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { DNSZone } from '@/types/infrastructure';

import { DNSZoneTable } from './dns-zone-table';

// The zone table lists zones, links to a zone's records and deletes a zone
// through the DNS service. Hooks and router are fakes; the Radix dropdown
// is flattened so its items are plain buttons.

const deleteZone = vi.fn();
const toast = vi.fn();
const push = vi.fn();

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push }),
}));

vi.mock('@/hooks', () => ({
  useDNS: () => ({ deleteZone }),
  useToast: () => ({ toast }),
  useMutation: <V, R>(
    fn: (v: V) => Promise<R>,
    opts?: { onSuccess?: (r: R) => void; onError?: (e: Error) => void },
  ) => {
    const [isLoading, setLoading] = useState(false);
    return {
      isLoading,
      mutate: async (v: V) => {
        setLoading(true);
        try {
          const r = await fn(v);
          setLoading(false);
          opts?.onSuccess?.(r);
        } catch (e) {
          setLoading(false);
          opts?.onError?.(e as Error);
        }
      },
    };
  },
}));

vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: ({ children, onClick }: { children: ReactNode; onClick?: () => void }) => (
    <button type="button" role="menuitem" onClick={onClick}>
      {children}
    </button>
  ),
}));

const NOW = new Date('2026-11-12T12:00:00Z');

function zone(overrides: Partial<DNSZone> = {}): DNSZone {
  return {
    id: 'z1',
    name: 'example.test',
    type: 'primary',
    recordCount: 12,
    serial: 2026111201,
    createdAt: '2026-11-10T12:00:00Z',
    ...overrides,
  } as DNSZone;
}

function rowOf(text: string): HTMLElement {
  return screen.getByText(text).closest('tr') as HTMLElement;
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  deleteZone.mockReset().mockResolvedValue({ success: true });
  toast.mockReset();
  push.mockReset();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe('DNSZoneTable', () => {
  it('shows the empty state across every column when there are no zones', () => {
    render(<DNSZoneTable zones={[]} onRefresh={vi.fn()} />);
    expect(screen.getByText('No DNS zones found').getAttribute('colspan')).toBe('6');
    for (const h of ['Zone Name', 'Type', 'Records', 'Serial', 'Created', 'Actions']) {
      expect(screen.getByRole('columnheader', { name: h })).toBeTruthy();
    }
    expect(screen.queryByRole('menuitem')).toBeNull();
  });

  it('renders the zone name, type, record count, serial and age', () => {
    render(<DNSZoneTable zones={[zone()]} onRefresh={vi.fn()} />);
    const row = within(rowOf('example.test'));
    expect(row.getByText('primary').className).toContain('bg-blue-500/10');
    expect(row.getByText('12')).toBeTruthy();
    expect(row.getByText('2026111201')).toBeTruthy();
    expect(row.getByText('2 days ago')).toBeTruthy();
  });

  it('colours a secondary zone grey', () => {
    render(<DNSZoneTable zones={[zone({ type: 'secondary' })]} onRefresh={vi.fn()} />);
    expect(within(rowOf('example.test')).getByText('secondary').className).toContain('bg-gray-500/10');
  });

  it.each([
    ['empty', ''],
    ['missing', undefined],
    ['unparsable', 'not-a-date'],
  ])('renders a dash for a %s creation time, not a fabricated age', (_label, createdAt) => {
    render(
      <DNSZoneTable zones={[zone({ createdAt: createdAt as unknown as string })]} onRefresh={vi.fn()} />,
    );
    const row = within(rowOf('example.test'));
    expect(row.getByText('—')).toBeTruthy();
    expect(row.queryByText(/ago/)).toBeNull();
  });

  it('opens the zone records page from View Records', () => {
    render(<DNSZoneTable zones={[zone({ name: 'lab.example.test' })]} onRefresh={vi.fn()} />);
    fireEvent.click(screen.getByRole('menuitem', { name: 'View Records' }));
    expect(push).toHaveBeenCalledWith('/networking/dns/lab.example.test');
    expect(deleteZone).not.toHaveBeenCalled();
  });

  it('deletes the zone by name, toasts and refreshes', async () => {
    const onRefresh = vi.fn();
    render(
      <DNSZoneTable zones={[zone(), zone({ id: 'z2', name: 'other.test' })]} onRefresh={onRefresh} />,
    );
    fireEvent.click(within(rowOf('other.test')).getByRole('menuitem', { name: 'Delete' }));
    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
    expect(deleteZone).toHaveBeenCalledWith('other.test');
    expect(toast).toHaveBeenCalledWith({ title: 'Success', description: 'DNS zone deleted successfully' });
  });

  it('toasts the error and does not refresh when the delete fails', async () => {
    deleteZone.mockRejectedValue(new Error('zone has records'));
    const onRefresh = vi.fn();
    render(<DNSZoneTable zones={[zone()]} onRefresh={onRefresh} />);
    fireEvent.click(screen.getByRole('menuitem', { name: 'Delete' }));
    await waitFor(() => expect(toast).toHaveBeenCalled());
    expect(toast).toHaveBeenCalledWith({
      title: 'Error',
      description: 'Failed to delete zone: zone has records',
      variant: 'destructive',
    });
    expect(onRefresh).not.toHaveBeenCalled();
  });

  it('disables the row actions while a delete runs', async () => {
    deleteZone.mockReturnValue(new Promise(() => {}));
    render(<DNSZoneTable zones={[zone()]} onRefresh={vi.fn()} />);
    const trigger = within(rowOf('example.test')).getAllByRole('button')[0] as HTMLButtonElement;
    expect(trigger.disabled).toBe(false);
    fireEvent.click(screen.getByRole('menuitem', { name: 'Delete' }));
    await waitFor(() => expect(trigger.disabled).toBe(true));
  });
});
