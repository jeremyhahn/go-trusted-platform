import type { ReactElement, ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Member, TenantRole } from '@/types/tenant';
import { MemberTable } from './member-table';

// #1818: the member table shows each member's name, email, initials, role
// and join date, sends a role change or a confirmed removal for that member,
// locks the member's row while it is pending, and logs a refusal.

// Opening a Radix menu in jsdom is slow, so the row menu renders its items
// inline; the item's onClick is the table's own.
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

// The role picker's popover honours open / onOpenChange and an item calls
// its onSelect on click; the role editor itself is real.
vi.mock('@/components/ui/popover', async () => {
  const R = await import('react');
  const Ctx = R.createContext<{ open: boolean; onOpenChange: (open: boolean) => void }>({
    open: false,
    onOpenChange: () => {},
  });
  return {
    Popover: ({
      open,
      onOpenChange,
      children,
    }: {
      open?: boolean;
      onOpenChange: (open: boolean) => void;
      children: ReactNode;
    }) => <Ctx.Provider value={{ open: !!open, onOpenChange }}>{children}</Ctx.Provider>,
    PopoverTrigger: ({ children }: { children: ReactElement<{ onClick?: () => void }> }) => {
      const ctx = R.useContext(Ctx);
      return R.cloneElement(children, { onClick: () => ctx.onOpenChange(!ctx.open) });
    },
    PopoverContent: ({ children }: { children: ReactNode }) => {
      const ctx = R.useContext(Ctx);
      return ctx.open ? <div>{children}</div> : null;
    },
  };
});

vi.mock('@/components/ui/command', () => ({
  Command: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  CommandList: ({ children }: { children: ReactNode }) => <div role="listbox">{children}</div>,
  CommandEmpty: () => null,
  CommandGroup: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  CommandItem: ({ children, onSelect }: { children: ReactNode; onSelect?: (value: string) => void }) => (
    <div role="option" aria-selected={false} onClick={() => onSelect?.('')}>
      {children}
    </div>
  ),
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function member(id: string, name: string, role: TenantRole, overrides: Partial<Member> = {}): Member {
  return {
    id,
    userId: `user-${id}`,
    user: { id: `user-${id}`, email: `${id}@example.com`, name },
    role,
    joinedAt: '2025-03-05T12:00:00Z',
    ...overrides,
  };
}

const members: Member[] = [
  member('m1', 'Ada Lovelace', 'owner'),
  member('m2', 'Grace Hopper', 'member', { joinedAt: '2024-11-20T12:00:00Z' }),
];

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

function row(name: string) {
  return screen.getByText(name).closest('tr') as HTMLTableRowElement;
}

function roleButton(name: string) {
  return within(row(name)).getByRole('combobox', { name: 'Select role' }) as HTMLButtonElement;
}

function menuButton(name: string) {
  return within(row(name)).getByRole('button', { name: 'Open menu' }) as HTMLButtonElement;
}

function pickRole(name: string, label: string) {
  fireEvent.click(roleButton(name));
  fireEvent.click(within(row(name)).getByRole('option', { name: new RegExp(`^${label}`) }));
}

function renderTable(props: Partial<Parameters<typeof MemberTable>[0]> = {}) {
  const onRoleChange = vi.fn<(memberId: string, role: TenantRole) => Promise<void>>().mockResolvedValue(undefined);
  const onRemove = vi.fn<(memberId: string) => Promise<void>>().mockResolvedValue(undefined);
  render(<MemberTable members={members} onRoleChange={onRoleChange} onRemove={onRemove} {...props} />);
  return { onRoleChange, onRemove };
}

describe('MemberTable', () => {
  it('renders the column headers', () => {
    renderTable();
    for (const header of ['Member', 'Role', 'Joined']) {
      expect(screen.getByRole('columnheader', { name: header })).toBeTruthy();
    }
  });

  it('renders each member with name, email, initials, role and join date', () => {
    renderTable();
    const ada = within(row('Ada Lovelace'));
    expect(ada.getByText('m1@example.com')).toBeTruthy();
    expect(ada.getByText('AL')).toBeTruthy();
    expect(ada.getByRole('combobox', { name: 'Select role' }).textContent).toBe('Owner');
    expect(ada.getByText('Mar 5, 2025')).toBeTruthy();

    const grace = within(row('Grace Hopper'));
    expect(grace.getByText('m2@example.com')).toBeTruthy();
    expect(grace.getByText('GH')).toBeTruthy();
    expect(grace.getByRole('combobox', { name: 'Select role' }).textContent).toBe('Member');
    expect(grace.getByText('Nov 20, 2024')).toBeTruthy();
  });

  it.each([
    ['plato', 'P'],
    ['jean claude van damme', 'JCVD'],
    ['a  b', 'AB'],
  ])('derives the initials of %j as %j', (name, initials) => {
    renderTable({ members: [member('x', name, 'viewer')] });
    expect(within(row('x@example.com')).getByText(initials)).toBeTruthy();
  });

  it('renders a member with an empty name without crashing', () => {
    renderTable({ members: [member('x', '', 'viewer')] });
    expect(screen.getByText('x@example.com')).toBeTruthy();
  });

  it('shows the empty state when there are no members', () => {
    renderTable({ members: [] });
    expect(screen.getByText('No results.')).toBeTruthy();
    expect(screen.queryByRole('combobox', { name: 'Select role' })).toBeNull();
  });

  it('sends a role change for that member', async () => {
    const { onRoleChange } = renderTable();
    pickRole('Grace Hopper', 'Admin');
    await waitFor(() => expect(onRoleChange).toHaveBeenCalledWith('m2', 'admin'));
    expect(onRoleChange).toHaveBeenCalledTimes(1);
    expect(roleButton('Ada Lovelace').textContent).toBe('Owner');
  });

  it('shows the role from the members it is given, not the one picked', async () => {
    const onRoleChange = vi.fn<(memberId: string, role: TenantRole) => Promise<void>>().mockResolvedValue(undefined);
    const onRemove = vi.fn<(memberId: string) => Promise<void>>().mockResolvedValue(undefined);
    const { rerender } = render(
      <MemberTable members={members} onRoleChange={onRoleChange} onRemove={onRemove} />,
    );
    pickRole('Grace Hopper', 'Admin');
    await waitFor(() => expect(roleButton('Grace Hopper').disabled).toBe(false));
    // The parent has not changed the member, so the row still shows its role.
    expect(roleButton('Grace Hopper').textContent).toBe('Member');

    rerender(
      <MemberTable
        members={[members[0], { ...members[1], role: 'admin' }]}
        onRoleChange={onRoleChange}
        onRemove={onRemove}
      />,
    );
    expect(roleButton('Grace Hopper').textContent).toBe('Admin');
  });

  it('locks only the member whose role change is pending', async () => {
    const pending = deferred();
    const onRoleChange = vi.fn(() => pending.promise);
    renderTable({ onRoleChange });
    pickRole('Ada Lovelace', 'Viewer');

    await waitFor(() => expect(roleButton('Ada Lovelace').disabled).toBe(true));
    expect(menuButton('Ada Lovelace').disabled).toBe(true);
    expect(roleButton('Grace Hopper').disabled).toBe(false);
    expect(menuButton('Grace Hopper').disabled).toBe(false);

    await act(async () => {
      pending.resolve();
      await pending.promise;
    });
    await waitFor(() => expect(roleButton('Ada Lovelace').disabled).toBe(false));
    expect(menuButton('Ada Lovelace').disabled).toBe(false);
  });

  it('logs a refused role change and unlocks the member', async () => {
    const err = new Error('forbidden');
    const onRoleChange = vi.fn().mockRejectedValue(err);
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    renderTable({ onRoleChange });
    pickRole('Grace Hopper', 'Owner');
    await waitFor(() => expect(logged).toHaveBeenCalledWith('Failed to update role:', err));
    await waitFor(() => expect(roleButton('Grace Hopper').disabled).toBe(false));
  });

  it('removes a member after the operator confirms', async () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const { onRemove } = renderTable();
    fireEvent.click(within(row('Grace Hopper')).getByRole('menuitem', { name: /remove member/i }));
    expect(confirm).toHaveBeenCalledWith('Are you sure you want to remove this member?');
    await waitFor(() => expect(onRemove).toHaveBeenCalledWith('m2'));
    expect(onRemove).toHaveBeenCalledTimes(1);
  });

  it('does not remove a member when the operator declines', () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    const { onRemove } = renderTable();
    fireEvent.click(within(row('Ada Lovelace')).getByRole('menuitem', { name: /remove member/i }));
    expect(onRemove).not.toHaveBeenCalled();
    expect(menuButton('Ada Lovelace').disabled).toBe(false);
  });

  it('locks the member while the removal is pending', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    const pending = deferred();
    const onRemove = vi.fn(() => pending.promise);
    renderTable({ onRemove });
    fireEvent.click(within(row('Ada Lovelace')).getByRole('menuitem', { name: /remove member/i }));
    await waitFor(() => expect(menuButton('Ada Lovelace').disabled).toBe(true));
    expect(roleButton('Ada Lovelace').disabled).toBe(true);
    expect(menuButton('Grace Hopper').disabled).toBe(false);

    await act(async () => {
      pending.resolve();
      await pending.promise;
    });
    await waitFor(() => expect(menuButton('Ada Lovelace').disabled).toBe(false));
  });

  it('logs a refused removal and unlocks the member', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    const err = new Error('last owner');
    const onRemove = vi.fn().mockRejectedValue(err);
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    renderTable({ onRemove });
    fireEvent.click(within(row('Ada Lovelace')).getByRole('menuitem', { name: /remove member/i }));
    await waitFor(() => expect(logged).toHaveBeenCalledWith('Failed to remove member:', err));
    await waitFor(() => expect(menuButton('Ada Lovelace').disabled).toBe(false));
    expect(screen.getByText('Ada Lovelace')).toBeTruthy();
  });

  it('locks every member while the table is loading', () => {
    const { onRoleChange } = renderTable({ isLoading: true });
    for (const name of ['Ada Lovelace', 'Grace Hopper']) {
      expect(roleButton(name).disabled).toBe(true);
      expect(menuButton(name).disabled).toBe(true);
    }
    fireEvent.click(roleButton('Ada Lovelace'));
    expect(screen.queryByRole('option')).toBeNull();
    expect(onRoleChange).not.toHaveBeenCalled();
  });

  it('offers the member search box', () => {
    renderTable();
    expect(screen.getByPlaceholderText('Search members...')).toBeTruthy();
  });
});
