import type { ReactElement, ReactNode } from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { TenantRole } from '@/types/tenant';
import { MemberRoleEditor } from './member-role-editor';

// #1818: the role picker shows the current role, lists the four roles with
// their descriptions, reports the picked role and closes, and does not open
// when disabled.

// The popover and command list are replaced by inline stand-ins: the popover
// honours open / onOpenChange, and an item calls its onSelect on click. The
// editor's own state and callbacks are real.
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
      return ctx.open ? <div data-testid="role-options">{children}</div> : null;
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

afterEach(cleanup);

const labels: Record<TenantRole, string> = {
  owner: 'Owner',
  admin: 'Admin',
  member: 'Member',
  viewer: 'Viewer',
};

function trigger() {
  return screen.getByRole('combobox', { name: 'Select role' }) as HTMLButtonElement;
}

function option(label: string) {
  return screen.getByRole('option', { name: new RegExp(`^${label}`) });
}

describe('MemberRoleEditor', () => {
  it.each(Object.entries(labels) as [TenantRole, string][])(
    'shows the %s role as its label on the closed trigger',
    (role, label) => {
      render(<MemberRoleEditor currentRole={role} onRoleChange={vi.fn()} />);
      expect(trigger().textContent).toBe(label);
      expect(trigger().getAttribute('aria-expanded')).toBe('false');
      expect(screen.queryByRole('option')).toBeNull();
    },
  );

  it('lists the four roles in order with their descriptions when opened', () => {
    render(<MemberRoleEditor currentRole="member" onRoleChange={vi.fn()} />);
    fireEvent.click(trigger());
    expect(trigger().getAttribute('aria-expanded')).toBe('true');
    const options = screen.getAllByRole('option');
    expect(options.map((o) => o.querySelector('p')?.textContent)).toEqual([
      'Owner',
      'Admin',
      'Member',
      'Viewer',
    ]);
    expect(screen.getByText('Full access to all settings')).toBeTruthy();
    expect(screen.getByText('Can manage members and settings')).toBeTruthy();
    expect(screen.getByText('Basic access to resources')).toBeTruthy();
    expect(screen.getByText('Read-only access to resources')).toBeTruthy();
  });

  it('marks only the current role as selected', () => {
    render(<MemberRoleEditor currentRole="admin" onRoleChange={vi.fn()} />);
    fireEvent.click(trigger());
    for (const label of Object.values(labels)) {
      const checked = option(label).querySelector('svg.opacity-100');
      if (label === 'Admin') {
        expect(checked).not.toBeNull();
      } else {
        expect(checked).toBeNull();
      }
    }
  });

  it('reports the picked role, closes and shows it on the trigger', () => {
    const onRoleChange = vi.fn();
    render(<MemberRoleEditor currentRole="member" onRoleChange={onRoleChange} />);
    fireEvent.click(trigger());
    fireEvent.click(option('Viewer'));
    expect(onRoleChange).toHaveBeenCalledTimes(1);
    expect(onRoleChange).toHaveBeenCalledWith('viewer');
    expect(screen.queryByRole('option')).toBeNull();
    expect(trigger().getAttribute('aria-expanded')).toBe('false');
    expect(trigger().textContent).toBe('Viewer');

    fireEvent.click(trigger());
    expect(option('Viewer').querySelector('svg.opacity-100')).not.toBeNull();
    expect(option('Member').querySelector('svg.opacity-100')).toBeNull();
  });

  it('reports the current role again when it is picked again', () => {
    const onRoleChange = vi.fn();
    render(<MemberRoleEditor currentRole="owner" onRoleChange={onRoleChange} />);
    fireEvent.click(trigger());
    fireEvent.click(option('Owner'));
    expect(onRoleChange).toHaveBeenCalledWith('owner');
    expect(trigger().textContent).toBe('Owner');
  });

  it('closes on a second trigger click without reporting a role', () => {
    const onRoleChange = vi.fn();
    render(<MemberRoleEditor currentRole="member" onRoleChange={onRoleChange} />);
    fireEvent.click(trigger());
    fireEvent.click(trigger());
    expect(screen.queryByRole('option')).toBeNull();
    expect(onRoleChange).not.toHaveBeenCalled();
  });

  it('does not open or report a role when disabled', () => {
    const onRoleChange = vi.fn();
    render(<MemberRoleEditor currentRole="admin" disabled onRoleChange={onRoleChange} />);
    expect(trigger().disabled).toBe(true);
    fireEvent.click(trigger());
    expect(screen.queryByRole('option')).toBeNull();
    expect(onRoleChange).not.toHaveBeenCalled();
    expect(trigger().textContent).toBe('Admin');
  });
});
