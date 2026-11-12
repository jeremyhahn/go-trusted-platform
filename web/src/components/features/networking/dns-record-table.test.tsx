import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { useState, type ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { DNSRecord } from '@/types/infrastructure';
import { toRecordType } from '@/utils/dns-record-type';

import { DNSRecordTable } from './dns-record-table';

// The record table lists a zone's records and deletes one through the DNS
// service. The hooks are fakes; the Radix dropdown (which does not open in
// jsdom) is flattened so its items are plain buttons.

const deleteRecord = vi.fn();
const toast = vi.fn();

vi.mock('@/hooks', () => ({
  useDNS: () => ({ deleteRecord }),
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

function rec(overrides: Partial<DNSRecord> = {}): DNSRecord {
  return {
    id: 'r1',
    name: 'www',
    type: 'A',
    value: '192.0.2.10',
    ttl: 300,
    ...overrides,
  } as DNSRecord;
}

function rowOf(text: string): HTMLElement {
  return screen.getByText(text).closest('tr') as HTMLElement;
}

beforeEach(() => {
  deleteRecord.mockReset().mockResolvedValue({ success: true });
  toast.mockReset();
});

afterEach(() => {
  cleanup();
});

describe('DNSRecordTable', () => {
  it('shows the empty state across every column when there are no records', () => {
    render(<DNSRecordTable zoneName="example.test" records={[]} onRefresh={vi.fn()} />);
    const cell = screen.getByText('No DNS records found');
    expect(cell.getAttribute('colspan')).toBe('6');
    for (const h of ['Name', 'Type', 'Value', 'TTL', 'Priority', 'Actions']) {
      expect(screen.getByRole('columnheader', { name: h })).toBeTruthy();
    }
    expect(screen.queryByRole('menuitem')).toBeNull();
  });

  it('renders one row per record with TTL in seconds and a dash for no priority', () => {
    render(
      <DNSRecordTable
        zoneName="example.test"
        records={[
          rec(),
          rec({ id: 'r2', name: '@', type: 'MX', value: 'mail.example.test', ttl: 3600, priority: 10 }),
          rec({ id: 'r3', name: 'zero', type: 'MX', value: 'mx0.example.test', priority: 0 }),
        ]}
        onRefresh={vi.fn()}
      />,
    );
    const a = within(rowOf('www'));
    expect(a.getByText('A')).toBeTruthy();
    expect(a.getByText('192.0.2.10')).toBeTruthy();
    expect(a.getByText('300s')).toBeTruthy();
    expect(a.getByText('-')).toBeTruthy();

    const mx = within(rowOf('mail.example.test'));
    expect(mx.getByText('3600s')).toBeTruthy();
    expect(mx.getByText('10')).toBeTruthy();

    // A priority of 0 is a value, not "missing".
    expect(within(rowOf('mx0.example.test')).getByText('0')).toBeTruthy();
  });

  it.each(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV'] as const)(
    'gives a %s record its own colour badge',
    (rrtype) => {
      render(
        <DNSRecordTable
          zoneName="example.test"
          records={[rec({ type: rrtype, name: 'n' })]}
          onRefresh={vi.fn()}
        />,
      );
      const badge = within(rowOf('n')).getByText(rrtype);
      expect(badge.className).toMatch(/bg-[a-z]+-500\/10/);
    },
  );

  it('offers Edit only when onEdit is given and passes the record', () => {
    const onEdit = vi.fn();
    const r = rec();
    const { rerender } = render(
      <DNSRecordTable zoneName="example.test" records={[r]} onRefresh={vi.fn()} />,
    );
    expect(screen.queryByRole('menuitem', { name: 'Edit' })).toBeNull();
    rerender(<DNSRecordTable zoneName="example.test" records={[r]} onRefresh={vi.fn()} onEdit={onEdit} />);
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit' }));
    expect(onEdit).toHaveBeenCalledWith(r);
    expect(deleteRecord).not.toHaveBeenCalled();
  });

  it('deletes the record by zone, type and name, toasts and refreshes', async () => {
    const onRefresh = vi.fn();
    render(
      <DNSRecordTable
        zoneName="example.test"
        records={[rec({ type: 'CNAME', name: 'alias', value: 'www.example.test' })]}
        onRefresh={onRefresh}
      />,
    );
    fireEvent.click(screen.getByRole('menuitem', { name: 'Delete' }));
    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
    expect(deleteRecord).toHaveBeenCalledWith({
      zoneName: 'example.test',
      type: toRecordType('CNAME'),
      name: 'alias',
    });
    expect(toast).toHaveBeenCalledWith({ title: 'Success', description: 'DNS record deleted successfully' });
  });

  it('toasts the error and does not refresh when the delete fails', async () => {
    deleteRecord.mockRejectedValue(new Error('not found'));
    const onRefresh = vi.fn();
    render(<DNSRecordTable zoneName="example.test" records={[rec()]} onRefresh={onRefresh} />);
    fireEvent.click(screen.getByRole('menuitem', { name: 'Delete' }));
    await waitFor(() => expect(toast).toHaveBeenCalled());
    expect(toast).toHaveBeenCalledWith({
      title: 'Error',
      description: 'Failed to delete record: not found',
      variant: 'destructive',
    });
    expect(onRefresh).not.toHaveBeenCalled();
  });

  it('disables the row actions while a delete runs', async () => {
    deleteRecord.mockReturnValue(new Promise(() => {}));
    render(<DNSRecordTable zoneName="example.test" records={[rec()]} onRefresh={vi.fn()} />);
    const trigger = within(rowOf('www')).getAllByRole('button')[0] as HTMLButtonElement;
    expect(trigger.disabled).toBe(false);
    fireEvent.click(screen.getByRole('menuitem', { name: 'Delete' }));
    await waitFor(() => expect(trigger.disabled).toBe(true));
  });
});
