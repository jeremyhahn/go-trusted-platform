import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { DeviceTemplate } from 'trusted-platform-sdk';

const h = vi.hoisted(() => ({
  push: vi.fn(),
  toast: vi.fn(),
  state: {} as Record<string, unknown>,
}));

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: h.push, back: vi.fn() }),
}));

vi.mock('@/hooks', () => ({
  useToast: () => ({ toast: h.toast }),
  useDeviceTemplates: () => h.state,
}));

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

vi.mock('@/components/ui/select', async () => {
  const React = await import('react');
  const Ctx = React.createContext<{ onValueChange?: (v: string) => void }>({});
  return {
    Select: ({
      children,
      name,
      value,
      defaultValue,
      onValueChange,
    }: {
      children: ReactNode;
      name?: string;
      value?: string;
      defaultValue?: string;
      onValueChange?: (v: string) => void;
    }) => (
      <Ctx.Provider value={{ onValueChange }}>
        <div data-testid={`select-${name ?? 'filter'}`} data-value={value}>
          {name && <input type="hidden" name={name} defaultValue={defaultValue} />}
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
        <button type="button" data-value={value} onClick={() => onValueChange?.(value)}>
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
    DialogFooter: ({ children }: { children: ReactNode }) => <div>{children}</div>,
    DialogTitle: ({ children }: { children: ReactNode }) => <h2>{children}</h2>,
    DialogDescription: ({ children }: { children: ReactNode }) => <p>{children}</p>,
  };
});

import DeviceTemplatesPage from './page';

function tpl(over: Partial<Record<keyof DeviceTemplate, unknown>>): DeviceTemplate {
  return {
    id: 1,
    name: 'Alpha',
    description: 'first template',
    role: 'server',
    config: { k: 'v' },
    match_rules: [],
    updated_at: '2026-01-15T12:00:00Z',
    ...over,
  } as unknown as DeviceTemplate;
}

function hookState(over: Record<string, unknown> = {}) {
  h.state = {
    templates: [],
    isLoading: false,
    error: null,
    refetch: vi.fn(),
    create: { mutateAsync: vi.fn().mockResolvedValue({}), isLoading: false },
    remove: { mutateAsync: vi.fn().mockResolvedValue(undefined), isLoading: false },
    ...over,
  };
  return h.state as {
    refetch: ReturnType<typeof vi.fn>;
    create: { mutateAsync: ReturnType<typeof vi.fn> };
    remove: { mutateAsync: ReturnType<typeof vi.fn> };
  };
}

function statValue(caption: string): string | null | undefined {
  return screen.getByText(caption).previousElementSibling?.textContent;
}

function rowFor(name: string): HTMLElement {
  return screen.getByText(name).closest('tr') as HTMLElement;
}

const confirmSpy = vi.fn(() => true);

beforeEach(() => {
  h.push.mockReset();
  h.toast.mockReset();
  confirmSpy.mockReset().mockReturnValue(true);
  vi.stubGlobal('confirm', confirmSpy);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('DeviceTemplatesPage', () => {
  describe('states', () => {
    it('shows the error alert with the message, and Retry refetches', () => {
      const s = hookState({ error: new Error('backend down') });
      render(<DeviceTemplatesPage />);
      expect(screen.getByText('Error Loading Templates')).toBeTruthy();
      expect(screen.getByText('backend down')).toBeTruthy();
      expect(screen.queryByText('Device Templates')).toBeNull();
      fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
      expect(s.refetch).toHaveBeenCalledTimes(1);
    });

    it('shows the loading state and disables Refresh while loading', () => {
      hookState({ isLoading: true });
      render(<DeviceTemplatesPage />);
      expect(screen.getByText('Loading templates...')).toBeTruthy();
      expect(screen.queryByRole('table')).toBeNull();
      expect((screen.getByRole('button', { name: 'Refresh' }) as HTMLButtonElement).disabled).toBe(true);
    });

    it('shows the empty message when there are no templates', () => {
      hookState();
      render(<DeviceTemplatesPage />);
      expect(screen.getByText('No device templates found')).toBeTruthy();
      expect(statValue('All device templates')).toBe('0');
      expect(statValue('Server templates')).toBe('0');
      expect(statValue('Edge and IoT templates')).toBe('0');
      expect(statValue('Gateway templates')).toBe('0');
    });

    it('Refresh calls refetch', () => {
      const s = hookState();
      render(<DeviceTemplatesPage />);
      fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
      expect(s.refetch).toHaveBeenCalledTimes(1);
    });
  });

  describe('statistics and rows', () => {
    it('counts templates by role, folding edge+iot and gateway+load-balancer', () => {
      hookState({
        templates: [
          tpl({ id: 1, name: 'S1', role: 'server' }),
          tpl({ id: 2, name: 'S2', role: 'server' }),
          tpl({ id: 3, name: 'E1', role: 'edge' }),
          tpl({ id: 4, name: 'I1', role: 'iot' }),
          tpl({ id: 5, name: 'G1', role: 'gateway' }),
          tpl({ id: 6, name: 'L1', role: 'load-balancer' }),
          tpl({ id: 7, name: 'U1', role: undefined }),
          tpl({ id: 8, name: 'W1', role: 'worker' }),
        ],
      });
      render(<DeviceTemplatesPage />);
      expect(statValue('All device templates')).toBe('8');
      expect(statValue('Server templates')).toBe('2');
      expect(statValue('Edge and IoT templates')).toBe('2');
      expect(statValue('Gateway templates')).toBe('2');
    });

    it('renders name, description, role label and formatted date', () => {
      hookState({ templates: [tpl({ name: 'Alpha', role: 'load-balancer' })] });
      render(<DeviceTemplatesPage />);
      const row = within(rowFor('Alpha'));
      expect(row.getByText('first template')).toBeTruthy();
      expect(row.getByText('Load Balancer')).toBeTruthy();
      expect(row.getByText('Jan 15, 2026')).toBeTruthy();
    });

    it('shows dashes for a missing description and a missing or invalid date', () => {
      hookState({
        templates: [
          tpl({ id: 1, name: 'NoDate', description: undefined, updated_at: null }),
          tpl({ id: 2, name: 'BadDate', description: '', updated_at: 'not-a-date' }),
        ],
      });
      render(<DeviceTemplatesPage />);
      for (const name of ['NoDate', 'BadDate']) {
        const row = within(rowFor(name));
        expect(row.getByText('-')).toBeTruthy();
        expect(row.getByText('—')).toBeTruthy();
      }
    });

    it('shows a role outside the SDK contract as sent', () => {
      hookState({ templates: [tpl({ name: 'Odd', role: 'mainframe' })] });
      render(<DeviceTemplatesPage />);
      expect(within(rowFor('Odd')).getByText('mainframe')).toBeTruthy();
    });
  });

  describe('filters', () => {
    const many = [
      tpl({ id: 11, name: 'Edge Box', description: 'rugged', role: 'edge' }),
      tpl({ id: 22, name: 'Rack Server', description: 'Datacenter unit', role: 'server' }),
      tpl({ id: 33, name: 'Plain', description: undefined, role: 'gateway' }),
    ];

    it('searches name, description and id, case-insensitively', () => {
      hookState({ templates: many });
      render(<DeviceTemplatesPage />);
      const search = screen.getByPlaceholderText('Search templates...');

      fireEvent.change(search, { target: { value: 'EDGE' } });
      expect(screen.queryByText('Edge Box')).toBeTruthy();
      expect(screen.queryByText('Rack Server')).toBeNull();

      fireEvent.change(search, { target: { value: 'datacenter' } });
      expect(screen.queryByText('Rack Server')).toBeTruthy();
      expect(screen.queryByText('Edge Box')).toBeNull();

      fireEvent.change(search, { target: { value: '33' } });
      expect(screen.queryByText('Plain')).toBeTruthy();
      expect(screen.queryByText('Rack Server')).toBeNull();
    });

    it('shows the no-match message and Clear filters restores every row', () => {
      hookState({ templates: many });
      render(<DeviceTemplatesPage />);
      expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull();
      fireEvent.change(screen.getByPlaceholderText('Search templates...'), {
        target: { value: 'zzz-nothing' },
      });
      expect(screen.getByText('No templates match your filters')).toBeTruthy();
      fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
      expect(screen.getByText('Edge Box')).toBeTruthy();
      expect(screen.getByText('Rack Server')).toBeTruthy();
      expect(screen.getByText('Plain')).toBeTruthy();
      expect((screen.getByPlaceholderText('Search templates...') as HTMLInputElement).value).toBe('');
    });

    it('filters by role, and "all" removes the role filter', () => {
      hookState({ templates: many });
      render(<DeviceTemplatesPage />);
      const filter = within(screen.getByTestId('select-filter'));
      expect(screen.getByTestId('select-filter').dataset.value).toBe('all');

      fireEvent.click(filter.getByRole('button', { name: 'Server' }));
      expect(screen.getByTestId('select-filter').dataset.value).toBe('server');
      expect(screen.getByText('Rack Server')).toBeTruthy();
      expect(screen.queryByText('Edge Box')).toBeNull();
      expect(screen.getByRole('button', { name: 'Clear filters' })).toBeTruthy();

      fireEvent.click(filter.getByRole('button', { name: 'All roles' }));
      expect(screen.getByTestId('select-filter').dataset.value).toBe('all');
      expect(screen.getByText('Edge Box')).toBeTruthy();
      expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull();
    });

    it('a role with no templates shows the no-match message', () => {
      hookState({ templates: many });
      render(<DeviceTemplatesPage />);
      fireEvent.click(within(screen.getByTestId('select-filter')).getByRole('button', { name: 'IoT' }));
      expect(screen.getByText('No templates match your filters')).toBeTruthy();
    });

    it('offers every SDK role, including Unknown, in the role filter', () => {
      hookState();
      render(<DeviceTemplatesPage />);
      const filter = within(screen.getByTestId('select-filter'));
      expect(filter.getByRole('button', { name: 'Unknown' })).toBeTruthy();
      expect(filter.getByRole('button', { name: 'Control Plane' })).toBeTruthy();
    });
  });

  describe('row actions', () => {
    it('View Details and Edit Template navigate to the template routes', () => {
      hookState({ templates: [tpl({ id: 42, name: 'Nav' })] });
      render(<DeviceTemplatesPage />);
      const row = within(rowFor('Nav'));
      fireEvent.click(row.getByText('View Details'));
      expect(h.push).toHaveBeenLastCalledWith('/devices/templates/42');
      fireEvent.click(row.getByText('Edit Template'));
      expect(h.push).toHaveBeenLastCalledWith('/devices/templates/42/edit');
    });

    it('Duplicate creates a copy, toasts success and refetches', async () => {
      const t = tpl({ id: 5, name: 'Orig', description: 'd', role: 'edge', config: { a: 1 }, match_rules: [{ x: 1 }] });
      const s = hookState({ templates: [t] });
      render(<DeviceTemplatesPage />);
      fireEvent.click(within(rowFor('Orig')).getByText('Duplicate'));
      await waitFor(() => expect(s.refetch).toHaveBeenCalledTimes(1));
      expect(s.create.mutateAsync).toHaveBeenCalledWith({
        name: 'Orig (Copy)',
        description: 'd',
        role: 'edge',
        config: { a: 1 },
        match_rules: [{ x: 1 }],
      });
      expect(h.toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'Template duplicated', description: '"Orig (Copy)" has been created', variant: 'success' })
      );
    });

    it('Duplicate failure toasts the error message and does not refetch', async () => {
      const s = hookState({ templates: [tpl({ name: 'Orig' })] });
      s.create.mutateAsync.mockRejectedValueOnce(new Error('name taken'));
      render(<DeviceTemplatesPage />);
      fireEvent.click(within(rowFor('Orig')).getByText('Duplicate'));
      await waitFor(() =>
        expect(h.toast).toHaveBeenCalledWith(
          expect.objectContaining({ title: 'Error duplicating template', description: 'name taken', variant: 'destructive' })
        )
      );
      expect(s.refetch).not.toHaveBeenCalled();
    });

    it('Duplicate failure with a non-Error value reports Unknown error', async () => {
      const s = hookState({ templates: [tpl({ name: 'Orig' })] });
      s.create.mutateAsync.mockRejectedValueOnce('nope');
      render(<DeviceTemplatesPage />);
      fireEvent.click(within(rowFor('Orig')).getByText('Duplicate'));
      await waitFor(() =>
        expect(h.toast).toHaveBeenCalledWith(expect.objectContaining({ description: 'Unknown error', variant: 'destructive' }))
      );
    });

    it('Delete asks for confirmation and does nothing when declined', () => {
      confirmSpy.mockReturnValue(false);
      const s = hookState({ templates: [tpl({ id: 9, name: 'Doomed' })] });
      render(<DeviceTemplatesPage />);
      fireEvent.click(within(rowFor('Doomed')).getByText('Delete'));
      expect(confirmSpy).toHaveBeenCalledWith('Are you sure you want to delete "Doomed"?');
      expect(s.remove.mutateAsync).not.toHaveBeenCalled();
      expect(h.toast).not.toHaveBeenCalled();
    });

    it('Delete, once confirmed, removes by id, toasts and refetches', async () => {
      const s = hookState({ templates: [tpl({ id: 9, name: 'Doomed' })] });
      render(<DeviceTemplatesPage />);
      fireEvent.click(within(rowFor('Doomed')).getByText('Delete'));
      await waitFor(() => expect(s.refetch).toHaveBeenCalledTimes(1));
      expect(s.remove.mutateAsync).toHaveBeenCalledWith(9);
      expect(h.toast).toHaveBeenCalledWith(expect.objectContaining({ title: 'Template deleted', variant: 'success' }));
    });

    it('Delete failure toasts the error and does not refetch', async () => {
      const s = hookState({ templates: [tpl({ name: 'Doomed' })] });
      s.remove.mutateAsync.mockRejectedValueOnce(new Error('in use'));
      render(<DeviceTemplatesPage />);
      fireEvent.click(within(rowFor('Doomed')).getByText('Delete'));
      await waitFor(() =>
        expect(h.toast).toHaveBeenCalledWith(
          expect.objectContaining({ title: 'Error deleting template', description: 'in use', variant: 'destructive' })
        )
      );
      expect(s.refetch).not.toHaveBeenCalled();
    });

    it('Delete failure with a non-Error value reports Unknown error', async () => {
      const s = hookState({ templates: [tpl({ name: 'Doomed' })] });
      s.remove.mutateAsync.mockRejectedValueOnce(42);
      render(<DeviceTemplatesPage />);
      fireEvent.click(within(rowFor('Doomed')).getByText('Delete'));
      await waitFor(() =>
        expect(h.toast).toHaveBeenCalledWith(
          expect.objectContaining({ title: 'Error deleting template', description: 'Unknown error' })
        )
      );
    });

    it('disables the row menu while a delete is in flight', () => {
      hookState({
        templates: [tpl({ name: 'Busy' })],
        remove: { mutateAsync: vi.fn(), isLoading: true },
      });
      render(<DeviceTemplatesPage />);
      const trigger = within(rowFor('Busy')).getByText('Open menu').closest('button') as HTMLButtonElement;
      expect(trigger.disabled).toBe(true);
    });
  });

  describe('create dialog', () => {
    function openDialog() {
      fireEvent.click(screen.getByRole('button', { name: 'Create Template' }));
      return within(screen.getByRole('dialog'));
    }

    it('opens and Cancel closes it', () => {
      hookState();
      render(<DeviceTemplatesPage />);
      expect(screen.queryByRole('dialog')).toBeNull();
      const dialog = openDialog();
      expect(dialog.getByText('Create Device Template')).toBeTruthy();
      fireEvent.click(dialog.getByRole('button', { name: 'Cancel' }));
      expect(screen.queryByRole('dialog')).toBeNull();
    });

    it('offers only assignable roles (no Unknown) and defaults to server', () => {
      hookState();
      render(<DeviceTemplatesPage />);
      const dialog = openDialog();
      expect(dialog.queryByRole('button', { name: 'Unknown' })).toBeNull();
      expect(dialog.getByRole('button', { name: 'Server' })).toBeTruthy();
      const role = screen.getByTestId('select-role').querySelector('input[name="role"]') as HTMLInputElement;
      expect(role.value).toBe('server');
    });

    it('submits name, description and role, toasts, refetches and closes', async () => {
      const s = hookState();
      render(<DeviceTemplatesPage />);
      const dialog = openDialog();
      fireEvent.change(dialog.getByLabelText('Template Name'), { target: { value: 'New One' } });
      fireEvent.change(dialog.getByLabelText('Description'), { target: { value: 'desc' } });
      fireEvent.submit(dialog.getByLabelText('Template Name').closest('form') as HTMLFormElement);
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
      expect(s.create.mutateAsync).toHaveBeenCalledWith({ name: 'New One', description: 'desc', role: 'server' });
      expect(s.refetch).toHaveBeenCalledTimes(1);
      expect(h.toast).toHaveBeenCalledWith(expect.objectContaining({ title: 'Template created', variant: 'success' }));
    });

    it('sends an empty description as undefined', async () => {
      const s = hookState();
      render(<DeviceTemplatesPage />);
      const dialog = openDialog();
      fireEvent.change(dialog.getByLabelText('Template Name'), { target: { value: 'Bare' } });
      fireEvent.submit(dialog.getByLabelText('Template Name').closest('form') as HTMLFormElement);
      await waitFor(() => expect(s.create.mutateAsync).toHaveBeenCalled());
      expect(s.create.mutateAsync).toHaveBeenCalledWith({ name: 'Bare', description: undefined, role: 'server' });
    });

    it('a role outside the SDK contract is refused before any request', async () => {
      const s = hookState();
      render(<DeviceTemplatesPage />);
      const dialog = openDialog();
      fireEvent.change(dialog.getByLabelText('Template Name'), { target: { value: 'Bad role' } });
      const role = screen.getByTestId('select-role').querySelector('input[name="role"]') as HTMLInputElement;
      role.value = 'mainframe';
      fireEvent.submit(dialog.getByLabelText('Template Name').closest('form') as HTMLFormElement);
      await waitFor(() =>
        expect(h.toast).toHaveBeenCalledWith(
          expect.objectContaining({ title: 'Error creating template', variant: 'destructive' })
        )
      );
      expect(String(h.toast.mock.calls[0][0].description)).toContain('mainframe');
      expect(s.create.mutateAsync).not.toHaveBeenCalled();
      expect(screen.getByRole('dialog')).toBeTruthy();
    });

    it('a failed create toasts the error and keeps the dialog open', async () => {
      const s = hookState();
      s.create.mutateAsync.mockRejectedValueOnce(new Error('quota'));
      render(<DeviceTemplatesPage />);
      const dialog = openDialog();
      fireEvent.change(dialog.getByLabelText('Template Name'), { target: { value: 'X' } });
      fireEvent.submit(dialog.getByLabelText('Template Name').closest('form') as HTMLFormElement);
      await waitFor(() =>
        expect(h.toast).toHaveBeenCalledWith(expect.objectContaining({ title: 'Error creating template', description: 'quota' }))
      );
      expect(s.refetch).not.toHaveBeenCalled();
      expect(screen.getByRole('dialog')).toBeTruthy();
    });

    it('a failed create with a non-Error value reports Unknown error', async () => {
      const s = hookState();
      s.create.mutateAsync.mockRejectedValueOnce(undefined);
      render(<DeviceTemplatesPage />);
      const dialog = openDialog();
      fireEvent.change(dialog.getByLabelText('Template Name'), { target: { value: 'X' } });
      fireEvent.submit(dialog.getByLabelText('Template Name').closest('form') as HTMLFormElement);
      await waitFor(() =>
        expect(h.toast).toHaveBeenCalledWith(expect.objectContaining({ description: 'Unknown error' }))
      );
    });

    it('disables the submit button while a create is in flight', () => {
      hookState({ create: { mutateAsync: vi.fn(), isLoading: true } });
      render(<DeviceTemplatesPage />);
      const dialog = openDialog();
      const submit = dialog
        .getAllByRole('button', { name: 'Create Template' })
        .find((b) => (b as HTMLButtonElement).type === 'submit') as HTMLButtonElement;
      expect(submit.disabled).toBe(true);
    });
  });
});
