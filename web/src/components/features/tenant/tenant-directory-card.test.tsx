import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { TenantDirectoryCard } from './tenant-directory-card';

// #2067: the tenant directory lists, creates, renames, deletes, suspends, resumes, finds and syncs
// tenants through the SDK TenantService, each control in the capability gate on its route.

const LIST = 'GET /api/v1/tenants';
const CREATE = 'POST /api/v1/tenants';
const UPDATE = 'PUT /api/v1/tenants/{id}';
const DELETE = 'DELETE /api/v1/tenants/{id}';
const SUSPEND = 'POST /api/v1/tenants/{id}/suspend';
const RESUME = 'POST /api/v1/tenants/{id}/resume';
const BY_NAME = 'GET /api/v1/tenants/by-name/{name}';
const SYNC = 'POST /api/v1/tenants/sync';
const ALL = [LIST, CREATE, UPDATE, DELETE, SUSPEND, RESUME, BY_NAME, SYNC];
const REASON = 'not-configured: tenant';

function caps(off: string[] = []): Answer {
  const capabilities = ALL.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: REASON }
      : { op, kind: 'route', enabled: true }
  );
  return ok({
    capabilities,
    total: capabilities.length,
    enabled: capabilities.filter((c) => c.enabled).length,
  });
}

const TENANTS = ok({
  tenants: [
    { id: 't1', name: 'acme', displayName: 'Acme', state: 'TENANT_STATE_ACTIVE' },
    { id: 't2', name: 'globex', state: 'TENANT_STATE_SUSPENDED' },
  ],
  total: 2,
});

function renderCard() {
  return render(withControlPlane(<TenantDirectoryCard />));
}

function listReads(sent: { method: string; path: string }[]) {
  return sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/tenants').length;
}

async function enabledButton(name: string, scope: HTMLElement = document.body) {
  const button = within(scope).getByRole('button', { name });
  await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
  return button;
}

describe('TenantDirectoryCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('lists the tenants the server answers', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps(), 'GET /api/v1/tenants': TENANTS });
    renderCard();

    const t1 = await screen.findByTestId('tenant-row-t1');
    expect(t1.textContent).toContain('acme');
    expect(t1.textContent).toContain('TENANT_STATE_ACTIVE');
    const t2 = screen.getByTestId('tenant-row-t2');
    expect(t2.textContent).toContain('globex');
    expect(t2.textContent).toContain('TENANT_STATE_SUSPENDED');
  });

  it('creates a tenant and re-reads the list', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'GET /api/v1/tenants': TENANTS,
      'POST /api/v1/tenants': ok({ tenant: { id: 't3', name: 'initech', state: 'TENANT_STATE_ACTIVE' } }),
    });
    renderCard();

    await waitFor(() => expect(listReads(sent)).toBe(1));
    fireEvent.change(screen.getByLabelText('Tenant name'), { target: { value: 'initech' } });
    fireEvent.click(await enabledButton('Create tenant'));

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'POST',
        path: '/api/v1/tenants',
        body: expect.objectContaining({ name: 'initech' }),
      })
    );
    await waitFor(() => expect(listReads(sent)).toBe(2));
  });

  it('renames a tenant through UpdateTenant', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'GET /api/v1/tenants': TENANTS,
      'PUT /api/v1/tenants/t1': ok({ tenant: { id: 't1', name: 'acme', displayName: 'Acme Corp' } }),
    });
    renderCard();

    const row = await screen.findByTestId('tenant-row-t1');
    fireEvent.click(await enabledButton('Edit', row));
    fireEvent.change(within(row).getByLabelText('Display name'), { target: { value: 'Acme Corp' } });
    fireEvent.click(await enabledButton('Save', row));

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'PUT',
        path: '/api/v1/tenants/t1',
        body: { tenantId: 't1', displayName: 'Acme Corp' },
      })
    );
  });

  it('deletes only after the confirm', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'GET /api/v1/tenants': TENANTS,
      'DELETE /api/v1/tenants/t1': ok({}),
    });
    renderCard();

    const row = await screen.findByTestId('tenant-row-t1');
    fireEvent.click(await enabledButton('Delete', row));
    expect(sent.some((r) => r.method === 'DELETE')).toBe(false);

    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Delete tenant acme?');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));

    await waitFor(() => expect(sent).toContainEqual(expect.objectContaining({ method: 'DELETE', path: '/api/v1/tenants/t1' })));
  });

  it('suspends an active tenant and resumes a suspended one', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'GET /api/v1/tenants': TENANTS,
      'POST /api/v1/tenants/t1/suspend': ok({}),
      'POST /api/v1/tenants/t2/resume': ok({}),
    });
    renderCard();

    const t1 = await screen.findByTestId('tenant-row-t1');
    expect(within(t1).queryByRole('button', { name: 'Resume' })).toBeNull();
    fireEvent.click(await enabledButton('Suspend', t1));
    await waitFor(() =>
      expect(sent).toContainEqual(expect.objectContaining({ method: 'POST', path: '/api/v1/tenants/t1/suspend' }))
    );

    const t2 = await screen.findByTestId('tenant-row-t2');
    expect(within(t2).queryByRole('button', { name: 'Suspend' })).toBeNull();
    fireEvent.click(await enabledButton('Resume', t2));
    await waitFor(() =>
      expect(sent).toContainEqual(expect.objectContaining({ method: 'POST', path: '/api/v1/tenants/t2/resume' }))
    );
  });

  // Codex P1 on PR #2372: a tenant past the first page must be reachable.
  const PAGE_ONE = ok({
    tenants: [
      { id: 't1', name: 'acme', state: 'TENANT_STATE_ACTIVE' },
      { id: 't2', name: 'globex', state: 'TENANT_STATE_ACTIVE' },
    ],
    total: 3,
  });
  const PAGE_TWO = ok({ tenants: [{ id: 't3', name: 'initech', state: 'TENANT_STATE_ACTIVE' }], total: 3 });

  function pageReads(sent: { method: string; path: string; query?: string }[]) {
    return sent
      .filter((r) => r.method === 'GET' && r.path === '/api/v1/tenants')
      .map((r) => new URLSearchParams(r.query ?? ''));
  }

  it('pages through the directory and shows the total', async () => {
    const routes: Record<string, Answer> = { 'GET /api/v1/capabilities': caps(), [LIST]: PAGE_ONE };
    const sent = stubControlPlane(routes);
    render(withControlPlane(<TenantDirectoryCard pageSize={2} />));

    await screen.findByTestId('tenant-row-t1');
    await waitFor(() => expect(screen.getByTestId('tenant-directory-total').textContent).toContain('3'));
    const first = pageReads(sent)[0];
    expect(first?.get('limit')).toBe('2');
    expect(first?.get('offset')).toBe('0');
    expect((screen.getByRole('button', { name: 'Previous page' }) as HTMLButtonElement).disabled).toBe(true);

    routes[LIST] = PAGE_TWO;
    fireEvent.click(await enabledButton('Next page'));
    await screen.findByTestId('tenant-row-t3');
    expect(screen.queryByTestId('tenant-row-t1')).toBeNull();
    expect(pageReads(sent).at(-1)?.get('offset')).toBe('2');
    expect((screen.getByRole('button', { name: 'Next page' }) as HTMLButtonElement).disabled).toBe(true);

    routes[LIST] = PAGE_ONE;
    fireEvent.click(await enabledButton('Previous page'));
    await screen.findByTestId('tenant-row-t1');
    expect(pageReads(sent).at(-1)?.get('offset')).toBe('0');
  });

  it('manages a tenant on the second page', async () => {
    const routes: Record<string, Answer> = {
      'GET /api/v1/capabilities': caps(),
      [LIST]: PAGE_ONE,
      'POST /api/v1/tenants/t3/suspend': ok({}),
    };
    const sent = stubControlPlane(routes);
    render(withControlPlane(<TenantDirectoryCard pageSize={2} />));

    await screen.findByTestId('tenant-row-t1');
    routes[LIST] = PAGE_TWO;
    fireEvent.click(await enabledButton('Next page'));
    const t3 = await screen.findByTestId('tenant-row-t3');
    const readsBefore = pageReads(sent).length;

    fireEvent.click(await enabledButton('Suspend', t3));
    await waitFor(() =>
      expect(sent).toContainEqual(expect.objectContaining({ method: 'POST', path: '/api/v1/tenants/t3/suspend' }))
    );
    await waitFor(() => expect(pageReads(sent).length).toBeGreaterThan(readsBefore));
    expect(pageReads(sent).at(-1)?.get('offset')).toBe('2');
  });

  it('finds a tenant by name', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'GET /api/v1/tenants': TENANTS,
      'GET /api/v1/tenants/by-name/acme': ok({
        tenant: { id: 't1', name: 'acme', displayName: 'Acme', state: 'TENANT_STATE_ACTIVE' },
      }),
    });
    renderCard();

    fireEvent.change(screen.getByLabelText('Find by name'), { target: { value: 'acme' } });
    fireEvent.click(await enabledButton('Find'));

    await waitFor(() =>
      expect(sent).toContainEqual(expect.objectContaining({ method: 'GET', path: '/api/v1/tenants/by-name/acme' }))
    );
    const result = await screen.findByTestId('tenant-lookup-result');
    await waitFor(() => expect(result.textContent).toContain('t1'));
    expect(result.textContent).toContain('acme');
  });

  it('syncs the tenants', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'GET /api/v1/tenants': TENANTS,
      'POST /api/v1/tenants/sync': ok({}),
    });
    renderCard();

    fireEvent.click(await enabledButton('Sync'));

    await waitFor(() =>
      expect(sent).toContainEqual(expect.objectContaining({ method: 'POST', path: '/api/v1/tenants/sync' }))
    );
    const toast = await screen.findByTestId('toast');
    expect(toast.getAttribute('data-variant')).not.toBe('destructive');
  });

  it('withholds every control the server does not offer', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps(ALL), 'GET /api/v1/tenants': TENANTS });
    renderCard();

    for (const [name, op] of [
      ['Create tenant', CREATE],
      ['Find', BY_NAME],
      ['Sync', SYNC],
    ] as const) {
      const button = screen.getByRole('button', { name });
      await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('false'));
      expect((button as HTMLButtonElement).disabled).toBe(true);
      expect(button.getAttribute('data-capability-op')).toBe(op);
    }
    expect((await screen.findAllByText(REASON)).length).toBeGreaterThan(0);
    expect(listReads(sent)).toBe(0);
    expect(sent.some((r) => r.method !== 'GET')).toBe(false);
  });

  it('shows a refused write as an error', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'GET /api/v1/tenants': TENANTS,
      'POST /api/v1/tenants': refused(409, 'tenant exists'),
    });
    renderCard();

    await waitFor(() => expect(listReads(sent)).toBe(1));
    fireEvent.change(screen.getByLabelText('Tenant name'), { target: { value: 'acme' } });
    fireEvent.click(await enabledButton('Create tenant'));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('tenant exists');
    expect(listReads(sent)).toBe(1);
  });
});
