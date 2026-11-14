import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';

type UseApiOptions = { onError?: (err: Error) => void };

const h = vi.hoisted(() => ({
  toast: vi.fn(),
  listBundles: vi.fn(),
  refetch: vi.fn(),
  api: { data: undefined as unknown, isLoading: false },
  calls: [] as { fetcher: () => unknown; deps: unknown[]; options: { onError?: (err: Error) => void } }[],
}));

vi.mock('@/hooks', () => ({
  useToast: () => ({ toast: h.toast }),
  useVTPM: () => ({ listBundles: h.listBundles }),
  useApi: (fetcher: () => unknown, deps: unknown[], options: UseApiOptions) => {
    h.calls.push({ fetcher, deps, options });
    return { data: h.api.data, isLoading: h.api.isLoading, refetch: h.refetch };
  },
}));

vi.mock('@/components/features/devices/vtpm-table', () => ({
  VTPMTable: ({ vtpms, onVTPMChange }: { vtpms: unknown[]; onVTPMChange: () => void }) => (
    <div>
      <pre data-testid="vtpm-table">{JSON.stringify(vtpms)}</pre>
      <button type="button" onClick={onVTPMChange}>
        table-change
      </button>
    </div>
  ),
}));

vi.mock('@/components/features/devices/vtpm-form', () => ({
  VTPMForm: ({ onSuccess, onCancel }: { onSuccess: () => void; onCancel: () => void }) => (
    <div>
      <button type="button" onClick={onSuccess}>
        form-success
      </button>
      <button type="button" onClick={onCancel}>
        form-cancel
      </button>
    </div>
  ),
}));

vi.mock('@/components/ui/select', async () => {
  const React = await import('react');
  const Ctx = React.createContext<{ onValueChange?: (v: string) => void }>({});
  return {
    Select: ({
      children,
      value,
      onValueChange,
    }: {
      children: ReactNode;
      value?: string;
      onValueChange?: (v: string) => void;
    }) => (
      <Ctx.Provider value={{ onValueChange }}>
        <div data-testid="select-state" data-value={value}>
          {children}
        </div>
      </Ctx.Provider>
    ),
    SelectTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
    SelectValue: ({ placeholder }: { placeholder?: string }) => <span>{placeholder}</span>,
    SelectContent: ({ children }: { children: ReactNode }) => <>{children}</>,
    SelectItem: ({ children, value }: { children: ReactNode; value: string }) => {
      const { onValueChange } = React.useContext(Ctx);
      return (
        <button type="button" onClick={() => onValueChange?.(value)}>
          {children}
        </button>
      );
    },
  };
});

vi.mock('@/components/ui/dialog', async () => {
  const React = await import('react');
  const Ctx = React.createContext<{ open: boolean; onOpenChange: (o: boolean) => void }>({
    open: false,
    onOpenChange: () => {},
  });
  return {
    Dialog: ({
      children,
      open,
      onOpenChange,
    }: {
      children: ReactNode;
      open: boolean;
      onOpenChange: (o: boolean) => void;
    }) => <Ctx.Provider value={{ open, onOpenChange }}>{children}</Ctx.Provider>,
    DialogTrigger: ({ children }: { children: ReactNode }) => {
      const { onOpenChange } = React.useContext(Ctx);
      return <span onClick={() => onOpenChange(true)}>{children}</span>;
    },
    DialogContent: ({ children }: { children: ReactNode }) => {
      const { open } = React.useContext(Ctx);
      return open ? <div role="dialog">{children}</div> : null;
    },
    DialogHeader: ({ children }: { children: ReactNode }) => <div>{children}</div>,
    DialogTitle: ({ children }: { children: ReactNode }) => <h2>{children}</h2>,
    DialogDescription: ({ children }: { children: ReactNode }) => <p>{children}</p>,
  };
});

import VTPMPage from './page';

interface Row {
  id: string;
  name: string;
  state: string;
  vmId: string;
  vmName?: string;
  tpmVersion: string;
  createdAt: string;
  updatedAt?: string;
  ekCertificate?: string;
  pcrProfile: string;
}

function rows(): Row[] {
  return JSON.parse(screen.getByTestId('vtpm-table').textContent ?? '[]');
}

function lastCall() {
  return h.calls[h.calls.length - 1];
}

const bundles = [
  { id: 'b-1', createdAt: '2026-01-01T00:00:00Z', manifest: { hostname: 'web-01', ekCertificate: { der: 'AA' } } },
  { id: 'b-2', createdAt: '2026-02-01T00:00:00Z', manifest: { hostname: 'DB-Primary' } },
  { id: 'vm-XYZ', manifest: {} },
];

beforeEach(() => {
  h.toast.mockReset();
  h.listBundles.mockReset();
  h.refetch.mockReset();
  h.calls.length = 0;
  h.api.data = { bundles };
  h.api.isLoading = false;
});

afterEach(() => cleanup());

describe('VTPMPage', () => {
  describe('data loading', () => {
    it('lists bundles through the SDK with a limit of 100', () => {
      render(<VTPMPage />);
      lastCall().fetcher();
      expect(h.listBundles).toHaveBeenCalledWith({ options: { limit: 100 } });
    });

    it('re-runs the request when a filter changes', () => {
      render(<VTPMPage />);
      expect(lastCall().deps).toEqual([undefined, undefined, undefined]);
      fireEvent.change(screen.getByPlaceholderText('Filter by VM ID...'), { target: { value: 'b-' } });
      fireEvent.change(screen.getByPlaceholderText('Search vTPM instances...'), { target: { value: 'web' } });
      fireEvent.click(within(screen.getByTestId('select-state')).getByRole('button', { name: 'Sealed' }));
      expect(lastCall().deps).toEqual(['sealed', 'b-', 'web']);
    });

    it('toasts a destructive error when the request fails', () => {
      render(<VTPMPage />);
      lastCall().options.onError?.(new Error('listing refused'));
      expect(h.toast).toHaveBeenCalledWith({ title: 'Error', description: 'listing refused', variant: 'destructive' });
    });

    it('shows the loading state instead of the table', () => {
      h.api.isLoading = true;
      render(<VTPMPage />);
      expect(screen.getByText('Loading vTPM instances...')).toBeTruthy();
      expect(screen.queryByTestId('vtpm-table')).toBeNull();
    });

    it('passes an empty list when there is no data yet', () => {
      h.api.data = undefined;
      render(<VTPMPage />);
      expect(rows()).toEqual([]);
    });

    it('passes an empty list when the payload has no bundles', () => {
      h.api.data = {};
      render(<VTPMPage />);
      expect(rows()).toEqual([]);
    });
  });

  describe('bundle mapping', () => {
    it('maps a bundle with a manifest to a vTPM row', () => {
      render(<VTPMPage />);
      expect(rows()[0]).toEqual({
        id: 'b-1',
        name: 'web-01',
        state: 'active',
        vmId: 'b-1',
        vmName: 'web-01',
        tpmVersion: '2.0',
        createdAt: '2026-01-01T00:00:00Z',
        updatedAt: '2026-01-01T00:00:00Z',
        ekCertificate: JSON.stringify({ der: 'AA' }),
        pcrProfile: '',
      });
    });

    it('falls back to the id for the name and to now for a missing createdAt', () => {
      const before = Date.now();
      render(<VTPMPage />);
      const r = rows()[2];
      expect(r.name).toBe('vm-XYZ');
      expect(r.vmName).toBeUndefined();
      expect(r.updatedAt).toBeUndefined();
      expect(r.ekCertificate).toBeUndefined();
      const created = Date.parse(r.createdAt);
      expect(Number.isFinite(created)).toBe(true);
      expect(created).toBeGreaterThanOrEqual(before - 1000);
    });

    it('handles a bundle with no manifest at all', () => {
      h.api.data = { bundles: [{ id: 'bare' }] };
      render(<VTPMPage />);
      expect(rows()[0]).toMatchObject({ id: 'bare', name: 'bare', vmId: 'bare', state: 'active' });
    });
  });

  describe('filters', () => {
    it('searches name and id case-insensitively', () => {
      render(<VTPMPage />);
      const search = screen.getByPlaceholderText('Search vTPM instances...');
      fireEvent.change(search, { target: { value: 'db-primary' } });
      expect(rows().map((r) => r.id)).toEqual(['b-2']);
      fireEvent.change(search, { target: { value: 'VM-xyz' } });
      expect(rows().map((r) => r.id)).toEqual(['vm-XYZ']);
      fireEvent.change(search, { target: { value: 'no-such' } });
      expect(rows()).toEqual([]);
    });

    it('filters by VM ID substring, case-sensitively', () => {
      render(<VTPMPage />);
      const vm = screen.getByPlaceholderText('Filter by VM ID...');
      fireEvent.change(vm, { target: { value: 'b-' } });
      expect(rows().map((r) => r.id)).toEqual(['b-1', 'b-2']);
      fireEvent.change(vm, { target: { value: 'xyz' } });
      expect(rows()).toEqual([]);
    });

    it('combines search and VM ID filters', () => {
      render(<VTPMPage />);
      fireEvent.change(screen.getByPlaceholderText('Filter by VM ID...'), { target: { value: 'b-' } });
      fireEvent.change(screen.getByPlaceholderText('Search vTPM instances...'), { target: { value: 'web' } });
      expect(rows().map((r) => r.id)).toEqual(['b-1']);
    });

    it('a state filter does not drop rows client-side', () => {
      render(<VTPMPage />);
      fireEvent.click(within(screen.getByTestId('select-state')).getByRole('button', { name: 'Migrating' }));
      expect(screen.getByTestId('select-state').dataset.value).toBe('migrating');
      expect(rows()).toHaveLength(3);
    });

    it('choosing All states clears the state filter', () => {
      render(<VTPMPage />);
      const select = within(screen.getByTestId('select-state'));
      fireEvent.click(select.getByRole('button', { name: 'Suspended' }));
      expect(screen.getByRole('button', { name: 'Clear filters' })).toBeTruthy();
      fireEvent.click(select.getByRole('button', { name: 'All states' }));
      expect(screen.getByTestId('select-state').dataset.value).toBe('all');
      expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull();
    });

    it('Clear filters appears with any filter and resets them all', () => {
      render(<VTPMPage />);
      expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull();
      const search = screen.getByPlaceholderText('Search vTPM instances...') as HTMLInputElement;
      const vm = screen.getByPlaceholderText('Filter by VM ID...') as HTMLInputElement;
      fireEvent.change(search, { target: { value: 'web' } });
      fireEvent.change(vm, { target: { value: 'b-1' } });
      fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
      expect(search.value).toBe('');
      expect(vm.value).toBe('');
      expect(rows()).toHaveLength(3);
      expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull();
    });

    it('emptying a filter input removes that filter', () => {
      render(<VTPMPage />);
      const search = screen.getByPlaceholderText('Search vTPM instances...');
      fireEvent.change(search, { target: { value: 'web' } });
      fireEvent.change(search, { target: { value: '' } });
      expect(rows()).toHaveLength(3);
      expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull();
    });
  });

  describe('create dialog and table callbacks', () => {
    it('opens the create dialog, and the form cancel closes it without refetching', () => {
      render(<VTPMPage />);
      expect(screen.queryByRole('dialog')).toBeNull();
      fireEvent.click(screen.getByRole('button', { name: 'Create vTPM' }));
      expect(within(screen.getByRole('dialog')).getByText('Create New vTPM Instance')).toBeTruthy();
      fireEvent.click(screen.getByRole('button', { name: 'form-cancel' }));
      expect(screen.queryByRole('dialog')).toBeNull();
      expect(h.refetch).not.toHaveBeenCalled();
    });

    it('a successful create closes the dialog and refetches', () => {
      render(<VTPMPage />);
      fireEvent.click(screen.getByRole('button', { name: 'Create vTPM' }));
      fireEvent.click(screen.getByRole('button', { name: 'form-success' }));
      expect(screen.queryByRole('dialog')).toBeNull();
      expect(h.refetch).toHaveBeenCalledTimes(1);
    });

    it('a change reported by the table refetches', () => {
      render(<VTPMPage />);
      fireEvent.click(screen.getByRole('button', { name: 'table-change' }));
      expect(h.refetch).toHaveBeenCalledTimes(1);
    });
  });
});
