import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Permission } from '@/types/iam';
import { PermissionTree } from './permission-tree';

function perm(id: string, resource: string, action: string, description = ''): Permission {
  return { id, name: `${resource}:${action}`, resource, action, description };
}

const permissions: Permission[] = [
  perm('u-write', 'users', 'write', 'Change users'),
  perm('d-read', 'devices', 'read'),
  perm('u-read', 'users', 'read', 'List users'),
  perm('d-delete', 'devices', 'delete'),
];

function groupBox(resource: string) {
  return screen.getByRole('checkbox', { name: `Select all ${resource} permissions` });
}

describe('PermissionTree', () => {
  afterEach(() => {
    cleanup();
  });

  it('says so when there are no permissions', () => {
    render(<PermissionTree permissions={[]} selectedPermissionIds={[]} onChange={vi.fn()} />);

    expect(screen.getByText('No permissions available')).toBeDefined();
    expect(screen.queryByRole('checkbox')).toBeNull();
  });

  it('groups by resource in name order, with actions in name order and a count', () => {
    render(<PermissionTree permissions={[...permissions]} selectedPermissionIds={[]} onChange={vi.fn()} />);

    const headers = screen.getAllByRole('button', { expanded: true }).map((b) => b.textContent);
    expect(headers).toEqual(['devices(2)', 'users(2)']);

    const actions = ['delete', 'read', 'read', 'write'];
    expect(screen.getAllByText(/^(delete|read|write)$/).map((n) => n.textContent)).toEqual(actions);
    expect(screen.getByText('List users')).toBeDefined();
    expect(screen.getByText('Change users')).toBeDefined();
  });

  it('adds a permission when its row is clicked', () => {
    const onChange = vi.fn();
    render(<PermissionTree permissions={[...permissions]} selectedPermissionIds={['d-read']} onChange={onChange} />);

    fireEvent.click(screen.getByText('List users'));

    expect(onChange).toHaveBeenLastCalledWith(['d-read', 'u-read']);
  });

  it('removes a selected permission when its row is clicked', () => {
    const onChange = vi.fn();
    render(
      <PermissionTree permissions={[...permissions]} selectedPermissionIds={['d-read', 'u-read']} onChange={onChange} />
    );

    fireEvent.click(screen.getByText('List users'));

    expect(onChange).toHaveBeenLastCalledWith(['d-read']);
  });

  it('selects the whole group and keeps the ids of other groups, without duplicates', () => {
    const onChange = vi.fn();
    render(
      <PermissionTree permissions={[...permissions]} selectedPermissionIds={['d-read', 'u-read']} onChange={onChange} />
    );

    fireEvent.click(groupBox('users'));

    expect(onChange).toHaveBeenCalledTimes(1);
    expect([...onChange.mock.calls[0][0]].sort()).toEqual(['d-read', 'u-read', 'u-write']);
  });

  it('clears the whole group when every permission in it is selected', () => {
    const onChange = vi.fn();
    render(
      <PermissionTree
        permissions={[...permissions]}
        selectedPermissionIds={['u-read', 'u-write', 'd-read']}
        onChange={onChange}
      />
    );

    expect(groupBox('users').getAttribute('aria-checked')).toBe('true');
    fireEvent.click(groupBox('users'));

    expect(onChange).toHaveBeenCalledWith(['d-read']);
  });

  it('marks a partly selected group indeterminate and an unselected one unchecked', () => {
    render(<PermissionTree permissions={[...permissions]} selectedPermissionIds={['d-read']} onChange={vi.fn()} />);

    expect(groupBox('devices').getAttribute('aria-checked')).toBe('mixed');
    expect(groupBox('users').getAttribute('aria-checked')).toBe('false');
  });

  it('ignores a selected id that names no permission', () => {
    render(<PermissionTree permissions={[...permissions]} selectedPermissionIds={['no-such-id']} onChange={vi.fn()} />);

    expect(groupBox('devices').getAttribute('aria-checked')).toBe('false');
    expect(groupBox('users').getAttribute('aria-checked')).toBe('false');
  });

  it('disables every checkbox when disabled', () => {
    const onChange = vi.fn();
    render(<PermissionTree permissions={[...permissions]} selectedPermissionIds={[]} onChange={onChange} disabled />);

    for (const box of screen.getAllByRole('checkbox')) {
      expect(box.hasAttribute('disabled')).toBe(true);
    }
    fireEvent.click(groupBox('users'));
    expect(onChange).not.toHaveBeenCalled();
  });

  it('collapses a group and expands it again from its header', () => {
    render(<PermissionTree permissions={[...permissions]} selectedPermissionIds={[]} onChange={vi.fn()} />);

    const header = screen.getByRole('button', { name: 'users(2)' });
    fireEvent.click(header);
    expect(header.getAttribute('aria-expanded')).toBe('false');
    expect(screen.queryByText('List users')).toBeNull();

    fireEvent.click(header);
    expect(header.getAttribute('aria-expanded')).toBe('true');
    expect(screen.getByText('List users')).toBeDefined();
  });

  it('applies the class name to the empty and the filled tree', () => {
    const { container, rerender } = render(
      <PermissionTree permissions={[]} selectedPermissionIds={[]} onChange={vi.fn()} className="tree-x" />
    );
    expect(container.firstElementChild?.className).toContain('tree-x');

    rerender(
      <PermissionTree permissions={[...permissions]} selectedPermissionIds={[]} onChange={vi.fn()} className="tree-x" />
    );
    expect(container.firstElementChild?.className).toContain('tree-x');
  });
});
