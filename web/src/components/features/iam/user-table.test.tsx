import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { LegacyRole, LegacyUser } from '@/types/iam';
import { UserTable, createUserColumns } from './user-table';

vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuCheckboxItem: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuItem: ({ children, onClick }: { children: ReactNode; onClick?: () => void }) => (
    <div role="menuitem" onClick={onClick}>
      {children}
    </div>
  ),
}));

function role(id: string): LegacyRole {
  return { id, name: `role-${id}`, description: '', permissions: [], userCount: 0 };
}

const daysAgo = (n: number) => new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();

function user(over: Partial<LegacyUser>): LegacyUser {
  return {
    id: 'u',
    email: 'u@example.test',
    name: 'user',
    roles: [],
    permissions: [],
    status: 'active',
    createdAt: daysAgo(3),
    updatedAt: daysAgo(3),
    ...over,
  };
}

const ada = user({ id: 'u1', name: 'ada', email: 'ada@example.test', roles: [role('a'), role('b'), role('c'), role('d'), role('e')], lastLoginAt: daysAgo(1) });
const bob = user({ id: 'u2', name: 'Bob', email: 'bob@example.test', status: 'disabled', avatarUrl: '/bob.png' });
const cy = user({ id: 'u3', name: 'Cy', email: 'cy@example.test', status: 'pending', roles: [role('viewer')] });

function rowOf(text: string) {
  return screen.getByText(text).closest('tr') as HTMLElement;
}

describe('createUserColumns', () => {
  it('builds the select, user, roles, status, created, last login and actions columns in order', () => {
    const ids = createUserColumns().map((c) => ('accessorKey' in c ? c.accessorKey : c.id));

    expect(ids).toEqual(['select', 'name', 'roles', 'status', 'createdAt', 'lastLoginAt', 'actions']);
  });

  it('does not sort by roles', () => {
    const roles = createUserColumns().find((c) => 'accessorKey' in c && c.accessorKey === 'roles');

    expect(roles?.enableSorting).toBe(false);
  });
});

describe('UserTable', () => {
  afterEach(() => {
    cleanup();
  });

  it('shows each user with an initial or an avatar, the email and a status badge', () => {
    render(<UserTable users={[ada, bob, cy]} />);

    expect(within(rowOf('ada@example.test')).getByText('A')).toBeDefined();
    expect(within(rowOf('bob@example.test')).getByRole('img', { name: 'Bob' }).getAttribute('src')).toBe('/bob.png');
    expect(within(rowOf('ada@example.test')).getByText('Active')).toBeDefined();
    expect(within(rowOf('bob@example.test')).getByText('Disabled')).toBeDefined();
    expect(within(rowOf('cy@example.test')).getByText('Pending')).toBeDefined();
  });

  it('shows at most three roles and counts the rest, or says there are none', () => {
    render(<UserTable users={[ada, bob, cy]} />);

    const adaRow = within(rowOf('ada@example.test'));
    expect(adaRow.getAllByText(/^role-/).map((n) => n.textContent)).toEqual(['role-a', 'role-b', 'role-c']);
    expect(adaRow.getByText('+2')).toBeDefined();
    expect(within(rowOf('bob@example.test')).getByText('No roles')).toBeDefined();
    expect(within(rowOf('cy@example.test')).getByText('role-viewer')).toBeDefined();
  });

  it('shows the dates relative to now and Never for a user who never logged in', () => {
    render(<UserTable users={[ada, bob]} />);

    expect(within(rowOf('ada@example.test')).getByText('3 days ago')).toBeDefined();
    expect(within(rowOf('ada@example.test')).getByText('1 day ago')).toBeDefined();
    expect(within(rowOf('bob@example.test')).getByText('Never')).toBeDefined();
  });

  it('offers View, Edit, Disable and Delete for an active user and calls back with it', () => {
    const onView = vi.fn();
    const onEdit = vi.fn();
    const onDisable = vi.fn();
    const onDelete = vi.fn();
    render(<UserTable users={[ada]} onView={onView} onEdit={onEdit} onDisable={onDisable} onDelete={onDelete} />);

    const items = within(rowOf('ada@example.test')).getAllByRole('menuitem');
    expect(items.map((i) => i.textContent)).toEqual(['View', 'Edit', 'Disable', 'Delete']);
    for (const item of items) fireEvent.click(item);

    for (const cb of [onView, onEdit, onDisable, onDelete]) expect(cb).toHaveBeenCalledWith(ada);
  });

  it('offers Enable for a disabled user and neither for a pending one', () => {
    const onDisable = vi.fn();
    render(<UserTable users={[bob, cy]} onDisable={onDisable} />);

    const enable = within(rowOf('bob@example.test')).getByRole('menuitem', { name: 'Enable' });
    fireEvent.click(enable);
    expect(onDisable).toHaveBeenCalledWith(bob);
    expect(within(rowOf('cy@example.test')).queryByRole('menuitem')).toBeNull();
  });

  it('has no row menu when no action is given', () => {
    render(<UserTable users={[ada]} />);

    expect(screen.queryByRole('button', { name: 'Open menu' })).toBeNull();
  });

  it('opens a user when its row is clicked', () => {
    const onView = vi.fn();
    render(<UserTable users={[ada, bob]} onView={onView} />);

    fireEvent.click(screen.getByText('bob@example.test'));

    expect(onView).toHaveBeenCalledWith(bob);
  });

  it('filters by name from the search box', () => {
    render(<UserTable users={[ada, bob, cy]} />);

    fireEvent.change(screen.getByPlaceholderText('Search users...'), { target: { value: 'bob' } });

    expect(screen.getByText('bob@example.test')).toBeDefined();
    expect(screen.queryByText('ada@example.test')).toBeNull();
  });

  it('deletes the selected users in bulk', () => {
    const onBulkDelete = vi.fn();
    render(<UserTable users={[ada, bob, cy]} onBulkDelete={onBulkDelete} />);

    fireEvent.click(within(rowOf('ada@example.test')).getByRole('checkbox', { name: 'Select row' }));
    fireEvent.click(within(rowOf('cy@example.test')).getByRole('checkbox', { name: 'Select row' }));
    fireEvent.click(screen.getByRole('button', { name: 'Delete selected (2)' }));

    expect(onBulkDelete).toHaveBeenCalledWith([ada, cy]);
  });

  it('shows no bulk action without a bulk handler', () => {
    render(<UserTable users={[ada]} />);

    fireEvent.click(within(rowOf('ada@example.test')).getByRole('checkbox', { name: 'Select row' }));

    expect(screen.queryByRole('button', { name: /Delete selected/ })).toBeNull();
  });

  it('says there are no results for an empty list', () => {
    render(<UserTable users={[]} />);

    expect(screen.getByText('No results.')).toBeDefined();
  });

  it('shows no users while loading', () => {
    render(<UserTable users={[ada]} loading />);

    expect(screen.queryByText('ada@example.test')).toBeNull();
  });
});
