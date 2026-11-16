import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { cloneElement, createContext, useContext, type ReactElement, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { LegacyRole, LegacyUser } from '@/types/iam';
import { UserForm } from './user-form';

// A Radix checkbox inside a form measures itself; jsdom has no ResizeObserver.
vi.stubGlobal(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
);

// Same stand-in as role-picker.test.tsx: the Radix popover slows jsdom runs
// to minutes.
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
    // Portalled out of the form, as the real popover is.
    PopoverContent: ({ children }: { children: ReactNode }) =>
      useContext(Ctx).open ? createPortal(<div role="dialog">{children}</div>, document.body) : null,
  };
});

const roles: LegacyRole[] = [
  { id: 'admin', name: 'Admin', description: 'Everything', permissions: [], userCount: 1 },
  { id: 'viewer', name: 'Viewer', description: 'Read only', permissions: [], userCount: 3 },
];

const ada: LegacyUser = {
  id: 'u1',
  email: 'ada@example.test',
  name: 'Ada',
  roles: [roles[1]],
  permissions: [],
  status: 'pending',
  createdAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-01T00:00:00Z',
};

function fill(label: RegExp, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

async function save(label: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: label }));
  });
}

describe('UserForm', () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('renders nothing while closed', () => {
    render(<UserForm open={false} onOpenChange={vi.fn()} onSubmit={vi.fn()} roles={roles} />);

    expect(screen.queryByText('Create User')).toBeNull();
  });

  it('opens empty in create mode with the status active', () => {
    render(<UserForm open onOpenChange={vi.fn()} onSubmit={vi.fn()} roles={roles} />);

    expect(screen.getByText('Add a new user to the system.')).toBeDefined();
    expect((screen.getByLabelText(/^Name/) as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText(/^Email/) as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Status') as HTMLSelectElement).value).toBe('active');
    expect(screen.getByPlaceholderText('Min. 8 characters')).toBeDefined();
  });

  it('requires a name, an email and a password to create', async () => {
    const onSubmit = vi.fn();
    render(<UserForm open onOpenChange={vi.fn()} onSubmit={onSubmit} roles={roles} />);

    fill(/^Name/, '   ');
    await save('Create User');

    expect(screen.getByText('Name is required')).toBeDefined();
    expect(screen.getByText('Email is required')).toBeDefined();
    expect(screen.getByText('Password is required')).toBeDefined();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('refuses a malformed email and a short password', async () => {
    const onSubmit = vi.fn();
    render(<UserForm open onOpenChange={vi.fn()} onSubmit={onSubmit} roles={roles} />);

    fill(/^Name/, 'Ada');
    fill(/^Email/, 'ada@nowhere');
    fill(/^Password/, 'short');
    await save('Create User');

    expect(screen.getByText('Invalid email format')).toBeDefined();
    expect(screen.getByText('Password must be at least 8 characters')).toBeDefined();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('creates a user with the chosen roles and status, then closes', async () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    const onOpenChange = vi.fn();
    render(<UserForm open onOpenChange={onOpenChange} onSubmit={onSubmit} roles={roles} />);

    fill(/^Name/, 'Ada');
    fill(/^Email/, 'ada@example.test');
    fill(/^Password/, '12345678');
    fireEvent.click(screen.getByRole('button', { name: 'Select roles' }));
    fireEvent.click(screen.getByText('Everything'));
    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'disabled' } });
    await save('Create User');

    expect(onSubmit).toHaveBeenCalledWith({
      name: 'Ada',
      email: 'ada@example.test',
      password: '12345678',
      roleIds: ['admin'],
      status: 'disabled',
    });
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('prefills the user in edit mode and sends no password when left blank', async () => {
    const onSubmit = vi.fn();
    render(<UserForm open onOpenChange={vi.fn()} onSubmit={onSubmit} roles={roles} user={ada} />);

    expect(screen.getByText('Edit User')).toBeDefined();
    expect(screen.getByText('(leave blank to keep current)')).toBeDefined();
    expect((screen.getByLabelText(/^Name/) as HTMLInputElement).value).toBe('Ada');
    expect((screen.getByLabelText('Status') as HTMLSelectElement).value).toBe('pending');
    expect(screen.getByRole('button', { name: 'Remove Viewer' })).toBeDefined();

    await save('Update User');

    expect(onSubmit).toHaveBeenCalledWith({
      name: 'Ada',
      email: 'ada@example.test',
      roleIds: ['viewer'],
      status: 'pending',
    });
  });

  it('sends a new password in edit mode when one is typed', async () => {
    const onSubmit = vi.fn();
    render(<UserForm open onOpenChange={vi.fn()} onSubmit={onSubmit} roles={roles} user={ada} />);

    fill(/^Password/, 'new-secret-1');
    await save('Update User');

    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({ password: 'new-secret-1' }));
  });

  it('refuses a short new password in edit mode as it does on create', async () => {
    const onSubmit = vi.fn();
    render(<UserForm open onOpenChange={vi.fn()} onSubmit={onSubmit} roles={roles} user={ada} />);

    fill(/^Password/, 'abc');
    await save('Update User');

    expect(screen.getByText('Password must be at least 8 characters')).toBeDefined();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('refuses an emptied email in edit mode', async () => {
    const onSubmit = vi.fn();
    render(<UserForm open onOpenChange={vi.fn()} onSubmit={onSubmit} roles={roles} user={ada} />);

    fill(/^Email/, '');
    await save('Update User');

    expect(screen.getByText('Email is required')).toBeDefined();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('stays open and logs when the submit is refused', async () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    const onOpenChange = vi.fn();
    render(
      <UserForm open onOpenChange={onOpenChange} onSubmit={vi.fn().mockRejectedValue(new Error('taken'))} roles={roles} user={ada} />
    );

    await save('Update User');

    expect(logged).toHaveBeenCalledWith('Form submission error:', expect.any(Error));
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
  });

  it('cancels', () => {
    const onOpenChange = vi.fn();
    render(<UserForm open onOpenChange={onOpenChange} onSubmit={vi.fn()} roles={roles} />);

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('while loading, disables every input and says it is saving', () => {
    render(<UserForm open onOpenChange={vi.fn()} onSubmit={vi.fn()} roles={roles} user={ada} loading />);

    expect(screen.getByRole('button', { name: 'Saving...' }).hasAttribute('disabled')).toBe(true);
    expect((screen.getByLabelText(/^Name/) as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByLabelText('Status') as HTMLSelectElement).disabled).toBe(true);
    expect(screen.queryByRole('button', { name: 'Remove Viewer' })).toBeNull();
  });

  it('clears the edited user when it switches to create mode', () => {
    const { rerender } = render(<UserForm open onOpenChange={vi.fn()} onSubmit={vi.fn()} roles={roles} user={ada} />);

    rerender(<UserForm open onOpenChange={vi.fn()} onSubmit={vi.fn()} roles={roles} />);

    expect(screen.getByRole('button', { name: 'Create User' })).toBeDefined();
    expect((screen.getByLabelText(/^Name/) as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Status') as HTMLSelectElement).value).toBe('active');
  });
});
