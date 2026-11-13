import * as React from 'react';
import type { ReactElement, ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { SendInvitationInput } from '@/types/tenant';
import { InvitationForm } from './invitation-form';

// #1818: the invitation dialog sends the typed email and the picked role,
// closes and resets on success, stays open with the input kept on a
// refusal, and never sends an empty email.

// The role picker's popover and command list are replaced by inline
// stand-ins: the popover honours open / onOpenChange, and an item calls its
// onSelect on click. The role editor's own state and callbacks are real.
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

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function deferred() {
  let resolve!: () => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function openDialog() {
  fireEvent.click(screen.getByRole('button', { name: /send invitation/i }));
  return screen.getByRole('dialog');
}

function emailInput(dialog: HTMLElement) {
  return within(dialog).getByLabelText('Email Address') as HTMLInputElement;
}

function submitButton(dialog: HTMLElement) {
  return within(dialog).getByRole('button', { name: /send invitation|sending/i }) as HTMLButtonElement;
}

function pickRole(dialog: HTMLElement, label: string) {
  fireEvent.click(within(dialog).getByRole('combobox', { name: 'Select role' }));
  fireEvent.click(within(dialog).getByRole('option', { name: new RegExp(`^${label}`) }));
}

describe('InvitationForm', () => {
  it('renders the default trigger and keeps the dialog closed', () => {
    render(<InvitationForm onSubmit={vi.fn()} />);
    expect(screen.getByRole('button', { name: /send invitation/i })).toBeTruthy();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByText('Invite Team Member')).toBeNull();
  });

  it('renders a custom trigger in place of the default one', () => {
    render(<InvitationForm onSubmit={vi.fn()} trigger={<button type="button">Invite</button>} />);
    expect(screen.queryByRole('button', { name: /send invitation/i })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Invite' }));
    expect(screen.getByRole('dialog')).toBeTruthy();
    expect(screen.getByText('Invite Team Member')).toBeTruthy();
  });

  it('opens with an empty email, the member role and the submit disabled', () => {
    render(<InvitationForm onSubmit={vi.fn()} />);
    const dialog = openDialog();
    expect(emailInput(dialog).value).toBe('');
    expect(emailInput(dialog).type).toBe('email');
    expect(emailInput(dialog).required).toBe(true);
    expect(within(dialog).getByRole('combobox', { name: 'Select role' }).textContent).toContain('Member');
    expect(submitButton(dialog).disabled).toBe(true);
  });

  it('does not send when the form is submitted with an empty email', () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    render(<InvitationForm onSubmit={onSubmit} />);
    const dialog = openDialog();
    fireEvent.submit(dialog.querySelector('form') as HTMLFormElement);
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog')).toBeTruthy();
  });

  it('sends the email with the default member role and closes', async () => {
    const onSubmit = vi.fn<(data: SendInvitationInput) => Promise<void>>().mockResolvedValue(undefined);
    render(<InvitationForm onSubmit={onSubmit} />);
    const dialog = openDialog();
    fireEvent.change(emailInput(dialog), { target: { value: 'a@example.com' } });
    expect(submitButton(dialog).disabled).toBe(false);
    fireEvent.click(submitButton(dialog));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledWith({ email: 'a@example.com', role: 'member' });
  });

  it('sends the role picked in the role editor', async () => {
    const onSubmit = vi.fn<(data: SendInvitationInput) => Promise<void>>().mockResolvedValue(undefined);
    render(<InvitationForm onSubmit={onSubmit} />);
    const dialog = openDialog();
    fireEvent.change(emailInput(dialog), { target: { value: 'b@example.com' } });
    pickRole(dialog, 'Admin');
    expect(within(dialog).getByRole('combobox', { name: 'Select role' }).textContent).toContain('Admin');
    fireEvent.click(submitButton(dialog));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith({ email: 'b@example.com', role: 'admin' }));
  });

  it('resets the email and role after a successful send', async () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    render(<InvitationForm onSubmit={onSubmit} />);
    let dialog = openDialog();
    fireEvent.change(emailInput(dialog), { target: { value: 'c@example.com' } });
    pickRole(dialog, 'Viewer');
    fireEvent.click(submitButton(dialog));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());

    dialog = openDialog();
    expect(emailInput(dialog).value).toBe('');
    expect(within(dialog).getByRole('combobox', { name: 'Select role' }).textContent).toContain('Member');
  });

  it('shows the sending state and locks the form while the send is pending', async () => {
    const pending = deferred();
    const onSubmit = vi.fn(() => pending.promise);
    render(<InvitationForm onSubmit={onSubmit} />);
    const dialog = openDialog();
    fireEvent.change(emailInput(dialog), { target: { value: 'd@example.com' } });
    fireEvent.click(submitButton(dialog));

    await waitFor(() => expect(within(dialog).getByText('Sending...')).toBeTruthy());
    expect(submitButton(dialog).disabled).toBe(true);
    expect(emailInput(dialog).disabled).toBe(true);
    expect((within(dialog).getByRole('button', { name: 'Cancel' }) as HTMLButtonElement).disabled).toBe(true);
    expect(
      (within(dialog).getByRole('combobox', { name: 'Select role' }) as HTMLButtonElement).disabled,
    ).toBe(true);

    // Escape does not close the dialog while the send is pending.
    fireEvent.keyDown(dialog, { key: 'Escape' });
    expect(screen.getByRole('dialog')).toBeTruthy();

    await act(async () => {
      pending.resolve();
      await pending.promise;
    });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('keeps the dialog open with the input when the send is refused', async () => {
    const err = new Error('refused');
    const onSubmit = vi.fn().mockRejectedValue(err);
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(<InvitationForm onSubmit={onSubmit} />);
    const dialog = openDialog();
    fireEvent.change(emailInput(dialog), { target: { value: 'e@example.com' } });
    pickRole(dialog, 'Owner');
    fireEvent.click(submitButton(dialog));

    await waitFor(() => expect(logged).toHaveBeenCalledWith('Failed to send invitation:', err));
    await waitFor(() => expect(submitButton(dialog).disabled).toBe(false));
    expect(screen.getByRole('dialog')).toBeTruthy();
    expect(emailInput(dialog).value).toBe('e@example.com');
    expect(emailInput(dialog).disabled).toBe(false);
    expect(within(dialog).getByRole('combobox', { name: 'Select role' }).textContent).toContain('Owner');
    expect(within(dialog).queryByText('Sending...')).toBeNull();
  });

  it('cancel closes without sending and clears the input', () => {
    const onSubmit = vi.fn();
    render(<InvitationForm onSubmit={onSubmit} />);
    let dialog = openDialog();
    fireEvent.change(emailInput(dialog), { target: { value: 'f@example.com' } });
    pickRole(dialog, 'Admin');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(onSubmit).not.toHaveBeenCalled();

    dialog = openDialog();
    expect(emailInput(dialog).value).toBe('');
    expect(within(dialog).getByRole('combobox', { name: 'Select role' }).textContent).toContain('Member');
  });
});
