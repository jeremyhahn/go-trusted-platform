import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { cloneElement, createContext, useContext, type ReactElement, type ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

// The Radix popover keeps positioning work running in jsdom and slows the
// run to minutes; a plain stand-in keeps its open/onOpenChange contract.
vi.mock('@/components/ui/popover', () => {
  const Ctx = createContext<{ open: boolean; onOpenChange: (open: boolean) => void }>({
    open: false,
    onOpenChange: () => {},
  });
  return {
    Popover: ({ open, onOpenChange, children }: { open: boolean; onOpenChange: (o: boolean) => void; children: ReactNode }) => (
      <Ctx.Provider value={{ open, onOpenChange }}>{children}</Ctx.Provider>
    ),
    PopoverTrigger: ({ children }: { children: ReactElement<{ onClick?: () => void }> }) => {
      const { open, onOpenChange } = useContext(Ctx);
      return cloneElement(children, { onClick: () => onOpenChange(!open) });
    },
    PopoverContent: ({ children }: { children: ReactNode }) =>
      useContext(Ctx).open ? <div role="dialog">{children}</div> : null,
  };
});

import type { LegacyRole, Permission } from '@/types/iam';
import { RolePicker } from './role-picker';

const read: Permission = { id: 'p1', name: 'users:read', resource: 'users', action: 'read', description: '' };
const write: Permission = { id: 'p2', name: 'users:write', resource: 'users', action: 'write', description: '' };

const roles: LegacyRole[] = [
  { id: 'admin', name: 'Admin', description: 'Everything', permissions: [read, write], userCount: 1 },
  { id: 'viewer', name: 'Viewer', description: '', permissions: [read], userCount: 4 },
  { id: 'empty', name: 'Empty', description: 'No rights', permissions: [], userCount: 0 },
];

function openPicker(label: string) {
  fireEvent.click(screen.getByRole('button', { name: label }));
}

describe('RolePicker', () => {
  afterEach(() => {
    cleanup();
  });

  it('asks to select roles when none is selected and shows no badge', () => {
    render(<RolePicker roles={roles} selectedRoleIds={[]} onChange={vi.fn()} />);

    expect(screen.getByRole('button', { name: 'Select roles' })).toBeDefined();
    expect(screen.queryByRole('button', { name: /^Remove / })).toBeNull();
  });

  it('shows a badge per selected role and offers to add more', () => {
    render(<RolePicker roles={roles} selectedRoleIds={['viewer', 'admin']} onChange={vi.fn()} />);

    expect(screen.getByRole('button', { name: 'Add more roles' })).toBeDefined();
    expect(screen.getByRole('button', { name: 'Remove Admin' })).toBeDefined();
    expect(screen.getByRole('button', { name: 'Remove Viewer' })).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Remove Empty' })).toBeNull();
  });

  it('ignores a selected id that names no role', () => {
    render(<RolePicker roles={roles} selectedRoleIds={['ghost']} onChange={vi.fn()} />);

    expect(screen.getByRole('button', { name: 'Select roles' })).toBeDefined();
    expect(screen.queryByRole('button', { name: /^Remove / })).toBeNull();
  });

  it('removes a role from its badge', () => {
    const onChange = vi.fn();
    render(<RolePicker roles={roles} selectedRoleIds={['admin', 'viewer']} onChange={onChange} />);

    fireEvent.click(screen.getByRole('button', { name: 'Remove Admin' }));

    expect(onChange).toHaveBeenCalledWith(['viewer']);
  });

  it('lists every role with its description and permission count', () => {
    render(<RolePicker roles={roles} selectedRoleIds={[]} onChange={vi.fn()} />);
    openPicker('Select roles');

    expect(screen.getByText('Everything')).toBeDefined();
    expect(screen.getByText('No rights')).toBeDefined();
    const counts = screen.getAllByText(/permission/).map((n) => n.textContent);
    expect(counts).toEqual(['2 permissions', '1 permission', '0 permissions']);
  });

  it('adds a role when its row is clicked', () => {
    const onChange = vi.fn();
    render(<RolePicker roles={roles} selectedRoleIds={['viewer']} onChange={onChange} />);
    openPicker('Add more roles');

    fireEvent.click(screen.getByText('Everything'));

    expect(onChange).toHaveBeenLastCalledWith(['viewer', 'admin']);
  });

  it('removes a selected role when its row is clicked', () => {
    const onChange = vi.fn();
    render(<RolePicker roles={roles} selectedRoleIds={['viewer', 'admin']} onChange={onChange} />);
    openPicker('Add more roles');

    fireEvent.click(screen.getByText('Everything'));

    expect(onChange).toHaveBeenLastCalledWith(['viewer']);
  });

  it('marks the selected roles checked in the list', () => {
    render(<RolePicker roles={roles} selectedRoleIds={['viewer']} onChange={vi.fn()} />);
    openPicker('Add more roles');

    const states = screen.getAllByRole('checkbox').map((b) => b.getAttribute('aria-checked'));
    expect(states).toEqual(['false', 'true', 'false']);
  });

  it('says so when there are no roles', () => {
    render(<RolePicker roles={[]} selectedRoleIds={['admin']} onChange={vi.fn()} />);
    openPicker('Select roles');

    expect(screen.getByText('No roles available')).toBeDefined();
    expect(screen.queryByRole('checkbox')).toBeNull();
  });

  it('when disabled, hides the remove buttons and cannot be opened', () => {
    render(<RolePicker roles={roles} selectedRoleIds={['admin']} onChange={vi.fn()} disabled />);

    expect(screen.queryByRole('button', { name: 'Remove Admin' })).toBeNull();
    const trigger = screen.getByRole('button', { name: 'Add more roles' });
    expect(trigger.hasAttribute('disabled')).toBe(true);
    fireEvent.click(trigger);
    expect(screen.queryByText('Everything')).toBeNull();
  });

  it('applies the class name', () => {
    const { container } = render(
      <RolePicker roles={roles} selectedRoleIds={[]} onChange={vi.fn()} className="picker-x" />
    );

    expect(container.firstElementChild?.className).toContain('picker-x');
  });
});
