import * as React from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { SendInvitationInput } from '@/types/tenant';
import { InvitationForm } from './invitation-form';

// #1818: the invitation dialog sends the typed email and the picked role,
// closes and resets on success, stays open with the input kept on a
// refusal, and never sends an empty email.

// #1992: the role select offers the tenant's IAM role names (the server
// accepts only those) and defaults to "user" when it is listed.
const ROLES = ['so', 'admin', 'operator', 'user', 'auditor', 'custodian'];

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

function roleSelect(dialog: HTMLElement) {
  return within(dialog).getByLabelText('Role') as HTMLSelectElement;
}

function pickRole(dialog: HTMLElement, name: string) {
  fireEvent.change(roleSelect(dialog), { target: { value: name } });
}

describe('InvitationForm', () => {
  it('renders the default trigger and keeps the dialog closed', () => {
    render(<InvitationForm onSubmit={vi.fn()} roles={ROLES} />);
    expect(screen.getByRole('button', { name: /send invitation/i })).toBeTruthy();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByText('Invite Team Member')).toBeNull();
  });

  it('renders a custom trigger in place of the default one', () => {
    render(<InvitationForm onSubmit={vi.fn()} roles={ROLES} trigger={<button type="button">Invite</button>} />);
    expect(screen.queryByRole('button', { name: /send invitation/i })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Invite' }));
    expect(screen.getByRole('dialog')).toBeTruthy();
    expect(screen.getByText('Invite Team Member')).toBeTruthy();
  });

  it('opens with an empty email, the user role and the submit disabled', () => {
    render(<InvitationForm onSubmit={vi.fn()} roles={ROLES} />);
    const dialog = openDialog();
    expect(emailInput(dialog).value).toBe('');
    expect(emailInput(dialog).type).toBe('email');
    expect(emailInput(dialog).required).toBe(true);
    expect(roleSelect(dialog).value).toBe('user');
    expect(submitButton(dialog).disabled).toBe(true);
  });

  it("offers exactly the tenant's IAM role names", () => {
    render(<InvitationForm onSubmit={vi.fn()} roles={ROLES} />);
    const dialog = openDialog();
    const offered = Array.from(roleSelect(dialog).options).map((o) => o.value);
    expect(offered).toEqual(ROLES);
  });

  it('defaults to the first role when "user" is not listed', () => {
    render(<InvitationForm onSubmit={vi.fn()} roles={['custom-a']} />);
    const dialog = openDialog();
    expect(roleSelect(dialog).value).toBe('custom-a');
  });

  it('keeps the submit disabled when the tenant has no roles', () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    render(<InvitationForm onSubmit={onSubmit} roles={[]} />);
    const dialog = openDialog();
    fireEvent.change(emailInput(dialog), { target: { value: 'z@example.com' } });
    expect(submitButton(dialog).disabled).toBe(true);
    fireEvent.submit(dialog.querySelector('form') as HTMLFormElement);
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('does not send when the form is submitted with an empty email', () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    render(<InvitationForm onSubmit={onSubmit} roles={ROLES} />);
    const dialog = openDialog();
    fireEvent.submit(dialog.querySelector('form') as HTMLFormElement);
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog')).toBeTruthy();
  });

  it('sends the email with the default user role and closes', async () => {
    const onSubmit = vi.fn<(data: SendInvitationInput) => Promise<void>>().mockResolvedValue(undefined);
    render(<InvitationForm onSubmit={onSubmit} roles={ROLES} />);
    const dialog = openDialog();
    fireEvent.change(emailInput(dialog), { target: { value: 'a@example.com' } });
    expect(submitButton(dialog).disabled).toBe(false);
    fireEvent.click(submitButton(dialog));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledWith({ email: 'a@example.com', role: 'user' });
  });

  it('sends the role picked in the role select', async () => {
    const onSubmit = vi.fn<(data: SendInvitationInput) => Promise<void>>().mockResolvedValue(undefined);
    render(<InvitationForm onSubmit={onSubmit} roles={ROLES} />);
    const dialog = openDialog();
    fireEvent.change(emailInput(dialog), { target: { value: 'b@example.com' } });
    pickRole(dialog, 'auditor');
    expect(roleSelect(dialog).value).toBe('auditor');
    fireEvent.click(submitButton(dialog));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith({ email: 'b@example.com', role: 'auditor' }));
  });

  it('resets the email and role after a successful send', async () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    render(<InvitationForm onSubmit={onSubmit} roles={ROLES} />);
    let dialog = openDialog();
    fireEvent.change(emailInput(dialog), { target: { value: 'c@example.com' } });
    pickRole(dialog, 'operator');
    fireEvent.click(submitButton(dialog));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());

    dialog = openDialog();
    expect(emailInput(dialog).value).toBe('');
    expect(roleSelect(dialog).value).toBe('user');
  });

  it('shows the sending state and locks the form while the send is pending', async () => {
    const pending = deferred();
    const onSubmit = vi.fn(() => pending.promise);
    render(<InvitationForm onSubmit={onSubmit} roles={ROLES} />);
    const dialog = openDialog();
    fireEvent.change(emailInput(dialog), { target: { value: 'd@example.com' } });
    fireEvent.click(submitButton(dialog));

    await waitFor(() => expect(within(dialog).getByText('Sending...')).toBeTruthy());
    expect(submitButton(dialog).disabled).toBe(true);
    expect(emailInput(dialog).disabled).toBe(true);
    expect((within(dialog).getByRole('button', { name: 'Cancel' }) as HTMLButtonElement).disabled).toBe(true);
    expect(roleSelect(dialog).disabled).toBe(true);

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
    render(<InvitationForm onSubmit={onSubmit} roles={ROLES} />);
    const dialog = openDialog();
    fireEvent.change(emailInput(dialog), { target: { value: 'e@example.com' } });
    pickRole(dialog, 'so');
    fireEvent.click(submitButton(dialog));

    await waitFor(() => expect(logged).toHaveBeenCalledWith('Failed to send invitation:', err));
    await waitFor(() => expect(submitButton(dialog).disabled).toBe(false));
    expect(screen.getByRole('dialog')).toBeTruthy();
    expect(emailInput(dialog).value).toBe('e@example.com');
    expect(emailInput(dialog).disabled).toBe(false);
    expect(roleSelect(dialog).value).toBe('so');
    expect(within(dialog).queryByText('Sending...')).toBeNull();
  });

  it('cancel closes without sending and clears the input', () => {
    const onSubmit = vi.fn();
    render(<InvitationForm onSubmit={onSubmit} roles={ROLES} />);
    let dialog = openDialog();
    fireEvent.change(emailInput(dialog), { target: { value: 'f@example.com' } });
    pickRole(dialog, 'admin');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(onSubmit).not.toHaveBeenCalled();

    dialog = openDialog();
    expect(emailInput(dialog).value).toBe('');
    expect(roleSelect(dialog).value).toBe('user');
  });
});
