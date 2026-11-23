import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ok,
  refused,
  stubControlPlane,
  withControlPlane,
  type Answer,
  type SentRequest,
} from '@/test/control-plane-fetch';
import { BMCAccountsCard } from './bmc-accounts-card';

// The users routes as the webservice serves them; each write control is gated on its own.
const LIST_OP = 'GET /api/v1/bmc/{profileID:[0-9]+}/users';
const CREATE_OP = 'POST /api/v1/bmc/{profileID:[0-9]+}/users';
const DELETE_OP = 'DELETE /api/v1/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}';
const PASSWORD_OP = 'PUT /api/v1/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}/password';
const PRIVILEGE_OP = 'PUT /api/v1/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}/privilege';
const OPS = [LIST_OP, CREATE_OP, DELETE_OP, PASSWORD_OP, PRIVILEGE_OP];

// caps answers the capabilities read: every users op enabled unless it is a key
// of off, whose value is the server's reason.
function caps(off: Record<string, string> = {}): Answer {
  const capabilities = OPS.map((op) =>
    op in off ? { op, kind: 'route', enabled: false, reason: off[op] } : { op, kind: 'route', enabled: true }
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function stub(routes: Record<string, Answer>, off: Record<string, string> = {}): SentRequest[] {
  return stubControlPlane({ 'GET /api/v1/capabilities': caps(off), ...routes });
}

// bmc drops the capabilities read so assertions see only the BMC requests.
function bmc(sent: SentRequest[]): SentRequest[] {
  return sent.filter((r) => r.path !== '/api/v1/capabilities');
}

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

// renderCard waits for the list and for the capabilities read, so a click
// lands on an enabled control; ready names a control whose op is on.
async function renderCard(ready = 'Set password for admin') {
  render(withControlPlane(<BMCAccountsCard profileID="42" />));
  await screen.findByTestId('bmc-user-2');
  await waitFor(() =>
    expect(screen.getByRole('button', { name: ready }).getAttribute('data-capability-enabled')).not.toBe('false')
  );
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
    stub(baseRoutes());
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
    const sent = stub({
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
    stub({
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
    const sent = stub(baseRoutes());
    await renderCard();

    fillCreate('user');
    change('Slot', '2');

    const create = screen.getByRole('button', { name: 'Create user' }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    expect(screen.getByText('Slot 2 is in use')).toBeDefined();
    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });

  it('asks before deleting and sends nothing on Cancel', async () => {
    const sent = stub(baseRoutes());
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
    const sent = stub({
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
    const sent = stub({
      ...baseRoutes(),
      'PUT /api/v1/bmc/42/users/3/password': ok({ status: 'ok' }),
      'PUT /api/v1/bmc/42/users/3/privilege': ok({ status: 'ok' }),
    });
    await renderCard();

    await click('Set password for operator1');
    await screen.findByRole('dialog');
    change('New password', RESET_PASSWORD);
    await click('Save password');

    expect(bmc(sent)).toContainEqual({
      method: 'PUT',
      path: '/api/v1/bmc/42/users/3/password',
      body: { password: RESET_PASSWORD },
    });
    expect(await screen.findByText('Password set: operator1')).toBeDefined();
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());

    change('Privilege for operator1', 'administrator');
    await click('Set privilege for operator1');

    expect(bmc(sent)).toContainEqual({
      method: 'PUT',
      path: '/api/v1/bmc/42/users/3/privilege',
      body: { privilege: 'administrator', channel: 1 },
    });
    expect(await screen.findByText('Privilege set: operator1 is now administrator')).toBeDefined();
  });

  it('shows an unknown profile on the list read', async () => {
    stub({ [USERS]: refused(404, 'bmc: profile 42 not found') });
    render(withControlPlane(<BMCAccountsCard profileID="42" />));

    const toast = await screen.findByText('BMC users unavailable: bmc: profile 42 not found');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.getByText('No BMC users')).toBeDefined();
  });

  it('gates every account control on its users route', async () => {
    stub(baseRoutes());
    await renderCard();

    const gated: Array<[string, string]> = [
      ['Create user', CREATE_OP],
      ['Set privilege for admin', PRIVILEGE_OP],
      ['Set password for admin', PASSWORD_OP],
      ['Delete admin', DELETE_OP],
    ];
    for (const [name, op] of gated) {
      const control = screen.getByRole('button', { name });
      expect(control.getAttribute('data-capability-op')).toBe(op);
      expect(control.getAttribute('data-capability-enabled')).toBe('true');
    }

    await click('Set password for admin');
    let dialog = await screen.findByRole('dialog');
    const save = within(dialog).getByRole('button', { name: 'Save password' });
    expect(save.getAttribute('data-capability-op')).toBe(PASSWORD_OP);
    expect(save.getAttribute('data-capability-enabled')).toBe('true');
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());

    await click('Delete admin');
    dialog = await screen.findByRole('dialog');
    const confirm = within(dialog).getByRole('button', { name: 'Confirm' });
    expect(confirm.getAttribute('data-capability-op')).toBe(DELETE_OP);
    expect(confirm.getAttribute('data-capability-enabled')).toBe('true');
  });

  it('disables the controls whose route the server does not offer, with the reason', async () => {
    const sent = stub(baseRoutes(), {
      [DELETE_OP]: 'scope bmc:admin required',
      [PASSWORD_OP]: 'scope bmc:admin required',
    });
    await renderCard('Set privilege for admin');

    for (const name of ['Delete admin', 'Set password for admin']) {
      const control = screen.getByRole('button', { name }) as HTMLButtonElement;
      expect(control.disabled).toBe(true);
      expect(control.getAttribute('title')).toBe('scope bmc:admin required');
      expect(control.getAttribute('data-capability-enabled')).toBe('false');
    }
    const privilege = screen.getByRole('button', { name: 'Set privilege for admin' }) as HTMLButtonElement;
    expect(privilege.disabled).toBe(false);

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Delete admin' }));
    });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(bmc(sent).some((r) => r.method === 'DELETE')).toBe(false);
  });
});
