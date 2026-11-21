import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { tenantStateLabel } from '@/hooks/use-tenant-state';
import { TenantStateCard } from './tenant-state-card';

// #2067: the tenant state card looks a tenant up by name through the SDK
// TenantService (GET /api/v1/tenants/by-name/{name}) and shows its state;
// a refusal is shown verbatim.

const BY_NAME = 'GET /api/v1/tenants/by-name/acme';

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function typeName(value: string) {
  fireEvent.change(screen.getByLabelText('Tenant name'), { target: { value } });
}

describe('TenantStateCard lookup', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('finds an active tenant', async () => {
    const sent = stubControlPlane({
      [BY_NAME]: ok({ tenant: { id: 't-1', name: 'acme', displayName: 'ACME', state: 'TENANT_STATE_ACTIVE' } }),
    });
    render(withControlPlane(<TenantStateCard />));
    typeName('acme');
    await click('Find');

    expect((await screen.findByTestId('tenant-state-id')).textContent).toContain('t-1');
    expect((screen.getByTestId('tenant-state-name')).textContent).toContain('ACME');
    expect((screen.getByTestId('tenant-state-badge')).textContent).toContain('ACTIVE');
    expect(sent.filter((r) => `${r.method} ${r.path}` === BY_NAME)).toHaveLength(1);
  });

  it('shows a suspended tenant', async () => {
    stubControlPlane({
      [BY_NAME]: ok({ tenant: { id: 't-1', name: 'acme', displayName: 'ACME', state: 'TENANT_STATE_SUSPENDED' } }),
    });
    render(withControlPlane(<TenantStateCard />));
    typeName('acme');
    await click('Find');

    expect((await screen.findByTestId('tenant-state-badge')).textContent).toContain('SUSPENDED');
  });

  it('shows an unknown name verbatim', async () => {
    stubControlPlane({ [BY_NAME]: refused(404, 'tenant not found') });
    render(withControlPlane(<TenantStateCard />));
    typeName('acme');
    await click('Find');

    expect((await screen.findByRole('alert')).textContent).toContain('tenant not found');
    expect(screen.queryByTestId('tenant-state-badge')).toBeNull();
  });

  it('needs a name', async () => {
    const sent = stubControlPlane({});
    render(withControlPlane(<TenantStateCard />));
    await click('Find');

    const toast = await screen.findByText('Name required: enter the tenant name');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(sent).toHaveLength(0);
  });

  it('labels states', () => {
    expect(tenantStateLabel('TENANT_STATE_DELETING')).toBe('DELETING');
    expect(tenantStateLabel('ACTIVE')).toBe('ACTIVE');
    expect(tenantStateLabel(undefined)).toBe('UNKNOWN');
    expect(tenantStateLabel('')).toBe('UNKNOWN');
  });
});
