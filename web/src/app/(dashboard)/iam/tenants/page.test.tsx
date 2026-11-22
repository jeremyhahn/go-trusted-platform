import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import TenantsPage from './page';

// #2053: the IAM tenants page lists the tenants (ListTenants), creates one
// (CreateTenant), opens one (GetTenant), renames it (UpdateTenant) and deletes
// it (DeleteTenant), all through the SDK's IAMService on the routed paths; a
// refusal reaches the operator with the server's message.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/iam/tenants',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const authResult = { tenantId: 'system', isLoading: false };

vi.mock('@/contexts/AuthContext', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/contexts/AuthContext')>()),
  useAuth: () => authResult,
}));

const LIST_PATH = 'GET /api/v1/iam/tenants';
const CREATE_PATH = 'POST /api/v1/iam/tenants';
const GET_PATH = 'GET /api/v1/iam/tenants/acme';
const PUT_PATH = 'PUT /api/v1/iam/tenants/acme';
const DELETE_PATH = 'DELETE /api/v1/iam/tenants/acme';

function tenantList(...tenants: Array<{ id: string; name: string }>): Answer {
  return ok({ tenants, total: tenants.length });
}

function toasts(prefix: string) {
  return screen.queryAllByTestId('toast').filter((t) => t.textContent?.startsWith(prefix));
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function listReadsAfter(sent: { method: string; path: string }[], index: number) {
  return sent.slice(index + 1).some((r) => r.method === 'GET' && r.path === '/api/v1/iam/tenants');
}

async function openAcme(routes: Record<string, Answer>) {
  const sent = stubControlPlane(routes);
  render(withControlPlane(<TenantsPage />));
  await screen.findByText('Acme Corp');
  await click('Open tenant acme');
  await screen.findByText('Tenant acme');
  await waitFor(() =>
    expect((screen.getByLabelText('Edit tenant name') as HTMLInputElement).value).toBe('Acme Corp')
  );
  return sent;
}

describe('TenantsPage', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('ListTenants: lists the tenants it reads', async () => {
    const sent = stubControlPlane({ [LIST_PATH]: tenantList({ id: 'acme', name: 'Acme Corp' }) });
    render(withControlPlane(<TenantsPage />));

    await screen.findByText('Acme Corp');
    expect(screen.getByText('acme')).toBeTruthy();
    expect(sent.some((r) => r.method === 'GET' && r.path === '/api/v1/iam/tenants')).toBe(true);
  });

  it("ListTenants: a refused list shows the server's message", async () => {
    stubControlPlane({ [LIST_PATH]: refused(403, 'system tenant only') });
    render(withControlPlane(<TenantsPage />));

    const alert = await screen.findByRole('alert');
    await waitFor(() => expect(alert.textContent).toContain('system tenant only'));
  });

  it('CreateTenant: sends the ID and name, toasts and re-reads the list', async () => {
    const sent = stubControlPlane({
      [LIST_PATH]: tenantList({ id: 'acme', name: 'Acme Corp' }),
      [CREATE_PATH]: ok({ tenant: { id: 'globex', name: 'Globex' } }),
    });
    render(withControlPlane(<TenantsPage />));
    await screen.findByText('Acme Corp');

    type('Tenant ID', 'globex');
    type('Tenant name', 'Globex');
    await click('Create tenant');

    await waitFor(() => expect(sent.some((r) => r.method === 'POST')).toBe(true));
    const post = sent.find((r) => r.method === 'POST');
    expect(post?.path).toBe('/api/v1/iam/tenants');
    expect(post?.body).toMatchObject({ id: 'globex', name: 'Globex' });
    await waitFor(() => expect(toasts('Tenant created').length).toBeGreaterThan(0));
    const postAt = sent.findIndex((r) => r.method === 'POST');
    await waitFor(() => expect(listReadsAfter(sent, postAt)).toBe(true));
  });

  it('CreateTenant: the button is disabled while the trimmed ID is empty', async () => {
    const sent = stubControlPlane({ [LIST_PATH]: tenantList({ id: 'acme', name: 'Acme Corp' }) });
    render(withControlPlane(<TenantsPage />));
    await screen.findByText('Acme Corp');

    type('Tenant ID', '   ');
    type('Tenant name', 'Globex');
    const button = screen.getByRole('button', { name: 'Create tenant' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    await click('Create tenant');
    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });

  it("CreateTenant: a refused create toasts the server's message", async () => {
    stubControlPlane({
      [LIST_PATH]: tenantList({ id: 'acme', name: 'Acme Corp' }),
      [CREATE_PATH]: refused(409, 'tenant globex already exists'),
    });
    render(withControlPlane(<TenantsPage />));
    await screen.findByText('Acme Corp');

    type('Tenant ID', 'globex');
    type('Tenant name', 'Globex');
    await click('Create tenant');

    await waitFor(() => {
      const failed = toasts('Failed to create tenant');
      expect(failed.length).toBeGreaterThan(0);
      expect(failed[0].textContent).toBe('Failed to create tenant: tenant globex already exists');
      expect(failed[0].getAttribute('data-variant')).toBe('destructive');
    });
  });

  it('GetTenant: opening a tenant reads it and seeds the editor', async () => {
    const sent = await openAcme({
      [LIST_PATH]: tenantList({ id: 'acme', name: 'Acme Corp' }),
      [GET_PATH]: ok({ id: 'acme', name: 'Acme Corp' }),
    });

    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/iam/tenants/acme', body: undefined });
  });

  it('UpdateTenant: sends the edited name and toasts Tenant updated', async () => {
    const routes: Record<string, Answer> = {
      [LIST_PATH]: tenantList({ id: 'acme', name: 'Acme Corp' }),
      [GET_PATH]: ok({ id: 'acme', name: 'Acme Corp' }),
      [PUT_PATH]: ok({ tenant: { id: 'acme', name: 'Acme Inc' } }),
    };
    const sent = await openAcme(routes);

    type('Edit tenant name', 'Acme Inc');
    routes[GET_PATH] = ok({ id: 'acme', name: 'Acme Inc' });
    await click('Save tenant');

    await waitFor(() => expect(sent.some((r) => r.method === 'PUT')).toBe(true));
    const put = sent.find((r) => r.method === 'PUT');
    expect(put?.path).toBe('/api/v1/iam/tenants/acme');
    expect(put?.body).toMatchObject({ tenantId: 'acme', name: 'Acme Inc' });
    await waitFor(() => expect(toasts('Tenant updated').length).toBeGreaterThan(0));
  });

  it("UpdateTenant: a refused update toasts the server's message", async () => {
    await openAcme({
      [LIST_PATH]: tenantList({ id: 'acme', name: 'Acme Corp' }),
      [GET_PATH]: ok({ id: 'acme', name: 'Acme Corp' }),
      [PUT_PATH]: refused(400, 'tenant name must not be empty'),
    });

    type('Edit tenant name', 'Acme Inc');
    await click('Save tenant');

    await waitFor(() => {
      const failed = toasts('Failed to update tenant');
      expect(failed.length).toBeGreaterThan(0);
      expect(failed[0].textContent).toBe('Failed to update tenant: tenant name must not be empty');
      expect(failed[0].getAttribute('data-variant')).toBe('destructive');
    });
  });

  it('DeleteTenant: deletes, toasts, closes the card and re-reads the list', async () => {
    const routes: Record<string, Answer> = {
      [LIST_PATH]: tenantList({ id: 'acme', name: 'Acme Corp' }),
      [GET_PATH]: ok({ id: 'acme', name: 'Acme Corp' }),
      [DELETE_PATH]: ok({ status: 'ok' }),
    };
    const sent = await openAcme(routes);

    routes[LIST_PATH] = tenantList();
    await click('Delete tenant');

    await waitFor(() => expect(sent.some((r) => r.method === 'DELETE')).toBe(true));
    expect(sent.find((r) => r.method === 'DELETE')?.path).toBe('/api/v1/iam/tenants/acme');
    await waitFor(() => expect(toasts('Tenant deleted').length).toBeGreaterThan(0));
    await waitFor(() => expect(screen.queryByText('Tenant acme')).toBeNull());
    const deleteAt = sent.findIndex((r) => r.method === 'DELETE');
    await waitFor(() => expect(listReadsAfter(sent, deleteAt)).toBe(true));
  });

  it("DeleteTenant: a refused delete toasts the server's message", async () => {
    await openAcme({
      [LIST_PATH]: tenantList({ id: 'acme', name: 'Acme Corp' }),
      [GET_PATH]: ok({ id: 'acme', name: 'Acme Corp' }),
      [DELETE_PATH]: refused(409, 'tenant acme still has users'),
    });

    await click('Delete tenant');

    await waitFor(() => {
      const failed = toasts('Failed to delete tenant');
      expect(failed.length).toBeGreaterThan(0);
      expect(failed[0].textContent).toBe('Failed to delete tenant: tenant acme still has users');
      expect(failed[0].getAttribute('data-variant')).toBe('destructive');
    });
  });
});
