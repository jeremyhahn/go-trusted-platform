import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { BMCAccountsCard } from './bmc-accounts-card';

// #2040: the BMC accounts card lists the users of one BMC profile and creates,
// deletes (after a confirm), re-passwords and re-privileges them through the
// SDK client; every refusal reaches the operator verbatim as a destructive toast.

const USERS = 'GET /api/v1/bmc/42/users';
// Test-only form values; no credential-shaped literal sits in the source.
const NEW_USER_PASSWORD = 'x'.repeat(16);
const RESET_PASSWORD = 'y'.repeat(16);

function baseRoutes(): Record<string, Answer> {
  return {
    [USERS]: ok([
      { slot: 2, username: 'admin', enabled: true, privilege: 4, channel: 1 },
      { slot: 3, username: 'operator1', enabled: false, privilege: 3, channel: 1 },
    ]),
  };
}

async function renderCard() {
  render(withControlPlane(<BMCAccountsCard profileID="42" />));
  await screen.findByTestId('bmc-user-2');
}

async function click(name: string) {
  const button = await screen.findByRole('button', { name });
  await act(async () => {
    fireEvent.click(button);
  });
}

function change(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function fillCreate(privilege: string) {
  change('Slot', '5');
  change('Username', ' viewer ');
  change('Password', NEW_USER_PASSWORD);
  change('Privilege', privilege);
}

describe('BMCAccountsCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('lists the users with privilege names', async () => {
    stubControlPlane(baseRoutes());
    render(withControlPlane(<BMCAccountsCard profileID="42" />));

    const admin = await screen.findByTestId('bmc-user-2');
    expect(admin.textContent).toContain('admin');
    expect(admin.textContent).toContain('Yes');
    expect(admin.textContent).toContain('administrator');
    const operator = screen.getByTestId('bmc-user-3');
    expect(operator.textContent).toContain('operator1');
    expect(operator.textContent).toContain('No');
    expect(operator.textContent).toContain('operator');
  });

  it('creates a user and re-reads the list', async () => {
    const sent = stubControlPlane({
      ...baseRoutes(),
      'POST /api/v1/bmc/42/users': ok({ slot: 5, username: 'viewer', enabled: true, privilege: 2, channel: 1 }),
    });
    await renderCard();

    const create = screen.getByRole('button', { name: 'Create user' }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    fillCreate('user');
    await click('Create user');

    const post = sent.filter((r) => r.method === 'POST');
    expect(post).toHaveLength(1);
    expect(post[0]).toEqual({
      method: 'POST',
      path: '/api/v1/bmc/42/users',
      body: { slot: 5, username: 'viewer', password: NEW_USER_PASSWORD, privilege: 'user', enabled: true, channel: 1 },
    });
    const toast = await screen.findByText('User created: viewer in slot 5');
    expect(toast.getAttribute('data-variant')).toBe('default');
    await waitFor(() => expect(sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/bmc/42/users')).toHaveLength(2));
    expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('');
  });

  it('shows the invalid privilege refusal and keeps the form', async () => {
    stubControlPlane({
      ...baseRoutes(),
      'POST /api/v1/bmc/42/users': refused(400, 'bmc: invalid privilege: no-access'),
    });
    await renderCard();

    fillCreate('no-access');
    await click('Create user');

    const toast = await screen.findByText('Create user failed: bmc: invalid privilege: no-access');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect((screen.getByLabelText('Username') as HTMLInputElement).value).toBe(' viewer ');
    expect((screen.getByLabelText('Password') as HTMLInputElement).value).toBe('');
  });

  it('blocks Create for a slot the list shows as used', async () => {
    const sent = stubControlPlane(baseRoutes());
    await renderCard();

    fillCreate('user');
    change('Slot', '2');

    const create = screen.getByRole('button', { name: 'Create user' }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    expect(screen.getByText('Slot 2 is in use')).toBeDefined();
    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });

  it('asks before deleting and sends nothing on Cancel', async () => {
    const sent = stubControlPlane(baseRoutes());
    await renderCard();

    await click('Delete operator1');
    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Delete operator1?');
    expect(dialog.textContent).toContain('This removes BMC slot 3 on profile 42.');
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    });

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(sent.some((r) => r.method === 'DELETE')).toBe(false);
  });

  it('deletes after the confirm', async () => {
    const sent = stubControlPlane({
      ...baseRoutes(),
      'DELETE /api/v1/bmc/42/users/3': ok({ status: 'ok' }),
    });
    await renderCard();

    await click('Delete operator1');
    await click('Confirm');

    const toast = await screen.findByText('User deleted: operator1');
    expect(toast.getAttribute('data-variant')).toBe('default');
    const deletes = sent.filter((r) => r.method === 'DELETE');
    expect(deletes).toHaveLength(1);
    expect(deletes[0].path).toBe('/api/v1/bmc/42/users/3');
  });

  it('sets a password and a privilege', async () => {
    const sent = stubControlPlane({
      ...baseRoutes(),
      'PUT /api/v1/bmc/42/users/3/password': ok({ status: 'ok' }),
      'PUT /api/v1/bmc/42/users/3/privilege': ok({ status: 'ok' }),
    });
    await renderCard();

    await click('Set password for operator1');
    await screen.findByRole('dialog');
    change('New password', RESET_PASSWORD);
    await click('Save password');

    expect(sent).toContainEqual({
      method: 'PUT',
      path: '/api/v1/bmc/42/users/3/password',
      body: { password: RESET_PASSWORD },
    });
    expect(await screen.findByText('Password set: operator1')).toBeDefined();
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());

    change('Privilege for operator1', 'administrator');
    await click('Set privilege for operator1');

    expect(sent).toContainEqual({
      method: 'PUT',
      path: '/api/v1/bmc/42/users/3/privilege',
      body: { privilege: 'administrator', channel: 1 },
    });
    expect(await screen.findByText('Privilege set: operator1 is now administrator')).toBeDefined();
  });

  it('shows an unknown profile on the list read', async () => {
    stubControlPlane({ [USERS]: refused(404, 'bmc: profile 42 not found') });
    render(withControlPlane(<BMCAccountsCard profileID="42" />));

    const toast = await screen.findByText('BMC users unavailable: bmc: profile 42 not found');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.getByText('No BMC users')).toBeDefined();
  });
});
