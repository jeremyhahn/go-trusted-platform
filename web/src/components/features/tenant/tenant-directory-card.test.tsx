import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import { TenantDirectoryCard } from './tenant-directory-card';

// #2067: the tenant directory card lists the tenants through the SDK's
// TenantService.listTenants (GET /tenants), creates one (POST /tenants),
// renames one through updateTenant (PUT /tenants/{id}) and deletes one behind
// a confirm (DELETE /tenants/{id}); every write re-lists, and a refusal
// reaches the operator verbatim as a destructive toast.

const LIST = 'GET /api/v1/tenants';
const CREATE = 'POST /api/v1/tenants';
const UPDATE = 'PUT /api/v1/tenants/t-2';
const DELETE = 'DELETE /api/v1/tenants/t-2';

const acme = { id: 't-1', name: 'acme', displayName: 'ACME', state: 'TENANT_STATE_ACTIVE' };
const globex = { id: 't-2', name: 'globex', displayName: 'Globex', state: 'TENANT_STATE_SUSPENDED' };

function listed(tenants: unknown[]): Answer {
  return ok({ tenants, total: tenants.length });
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function lists(sent: SentRequest[]): number {
  return sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/tenants').length;
}

async function relistedAfter(sent: SentRequest[], method: string) {
  const at = sent.findIndex((r) => r.method === method);
  expect(at).toBeGreaterThan(-1);
  await waitFor(() =>
    expect(sent.slice(at + 1).some((r) => r.method === 'GET' && r.path === '/api/v1/tenants')).toBe(true)
  );
}

async function destructiveToast(text: string) {
  const found = await screen.findAllByText((_, el) => el?.getAttribute('data-testid') === 'toast' && !!el.textContent?.includes(text));
  expect(found.some((t) => t.getAttribute('data-variant') === 'destructive')).toBe(true);
}

describe('TenantDirectoryCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('lists the tenants ListTenants returns', async () => {
    const sent = stubControlPlane({ [LIST]: listed([acme, globex]) });
    render(withControlPlane(<TenantDirectoryCard />));

    const row = await screen.findByTestId('tenant-row-t-2');
    expect(within(row).getByText('globex')).toBeTruthy();
    expect(within(row).getByText('Globex')).toBeTruthy();
    expect(within(row).getByText('SUSPENDED')).toBeTruthy();
    expect(within(screen.getByTestId('tenant-row-t-1')).getByText('ACTIVE')).toBeTruthy();
    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/tenants', body: undefined });
    expect(sent.some((r) => r.method !== 'GET')).toBe(false);
  });

  it('shows a refused list verbatim', async () => {
    stubControlPlane({ [LIST]: refused(403, 'only the system tenant may list tenants') });
    render(withControlPlane(<TenantDirectoryCard />));

    await destructiveToast('only the system tenant may list tenants');
  });

  it('creates a tenant and re-lists', async () => {
    const routes: Record<string, Answer> = {
      [LIST]: listed([acme]),
      [CREATE]: ok({ status: { success: true, message: 'created' }, tenant: { id: 't-3', name: 'initech', displayName: 'Initech', state: 'TENANT_STATE_ACTIVE' } }),
    };
    const sent = stubControlPlane(routes);
    render(withControlPlane(<TenantDirectoryCard />));
    await screen.findByTestId('tenant-row-t-1');

    type('New tenant name', ' initech ');
    type('New tenant display name', 'Initech');
    routes[LIST] = listed([acme, { id: 't-3', name: 'initech', displayName: 'Initech', state: 'TENANT_STATE_ACTIVE' }]);
    await click('Create');

    await waitFor(() =>
      expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/tenants', body: { name: 'initech', displayName: 'Initech' } })
    );
    await relistedAfter(sent, 'POST');
    await screen.findByTestId('tenant-row-t-3');
  });

  it('keeps the create form open on a refusal', async () => {
    const sent = stubControlPlane({ [LIST]: listed([acme]), [CREATE]: refused(409, 'tenant initech already exists') });
    render(withControlPlane(<TenantDirectoryCard />));
    await screen.findByTestId('tenant-row-t-1');

    type('New tenant name', 'initech');
    type('New tenant display name', 'Initech');
    await click('Create');

    await destructiveToast('tenant initech already exists');
    expect((screen.getByLabelText('New tenant name') as HTMLInputElement).value).toBe('initech');
    expect(screen.getByLabelText('New tenant display name')).toBeTruthy();
    expect(lists(sent)).toBe(1);
  });

  it('refuses an empty name without sending', async () => {
    const sent = stubControlPlane({ [LIST]: listed([acme]) });
    render(withControlPlane(<TenantDirectoryCard />));
    await screen.findByTestId('tenant-row-t-1');

    type('New tenant name', '   ');
    await click('Create');

    await destructiveToast('name');
    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });

  it('renames a tenant through UpdateTenant and re-lists', async () => {
    const routes: Record<string, Answer> = {
      [LIST]: listed([acme, globex]),
      [UPDATE]: ok({ status: { success: true, message: 'updated' }, tenant: { ...globex, displayName: 'Globex Corp' } }),
    };
    const sent = stubControlPlane(routes);
    render(withControlPlane(<TenantDirectoryCard />));
    const row = await screen.findByTestId('tenant-row-t-2');

    await act(async () => {
      fireEvent.click(within(row).getByRole('button', { name: 'Rename' }));
    });
    type('Display name for globex', 'Globex Corp');
    routes[LIST] = listed([acme, { ...globex, displayName: 'Globex Corp' }]);
    await click('Save');

    await waitFor(() => {
      const put = sent.find((r) => r.method === 'PUT');
      expect(put?.path).toBe('/api/v1/tenants/t-2');
      expect((put?.body as { displayName?: string } | undefined)?.displayName).toBe('Globex Corp');
    });
    await relistedAfter(sent, 'PUT');
    await screen.findByText('Globex Corp');
  });

  it('asks before deleting and sends nothing on Cancel', async () => {
    const sent = stubControlPlane({ [LIST]: listed([acme, globex]), [DELETE]: ok({ status: { success: true, message: 'deleted' } }) });
    render(withControlPlane(<TenantDirectoryCard />));
    const row = await screen.findByTestId('tenant-row-t-2');

    await act(async () => {
      fireEvent.click(within(row).getByRole('button', { name: 'Delete' }));
    });
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Delete globex?')).toBeTruthy();
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    });

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(sent.some((r) => r.method === 'DELETE')).toBe(false);
  });

  it('deletes after the confirm and re-lists', async () => {
    const routes: Record<string, Answer> = {
      [LIST]: listed([acme, globex]),
      [DELETE]: ok({ status: { success: true, message: 'deleted' } }),
    };
    const sent = stubControlPlane(routes);
    render(withControlPlane(<TenantDirectoryCard />));
    const row = await screen.findByTestId('tenant-row-t-2');

    await act(async () => {
      fireEvent.click(within(row).getByRole('button', { name: 'Delete' }));
    });
    const dialog = await screen.findByRole('dialog');
    expect(sent.some((r) => r.method === 'DELETE')).toBe(false);
    routes[LIST] = listed([acme]);
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
    });

    await waitFor(() => expect(sent).toContainEqual({ method: 'DELETE', path: '/api/v1/tenants/t-2', body: undefined }));
    await relistedAfter(sent, 'DELETE');
    await waitFor(() => expect(screen.queryByTestId('tenant-row-t-2')).toBeNull());
  });
});
