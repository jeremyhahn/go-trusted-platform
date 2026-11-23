import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import TenantPage from './page';

// #2067: the admin workspace page reads the tenant through the SDK's TenantService (GET /api/v1/tenants/{id}), not the unserved /api/v1/tenant.

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }));

const jwt = vi.hoisted(() => ({
  user: { tenantId: 't1', isTenantOwner: true } as { tenantId: string | null; isTenantOwner: boolean } | null,
}));
vi.mock('@/utils/jwt', () => ({ getUserFromToken: () => jwt.user }));

vi.mock('@/hooks/use-logout', () => ({ useLogout: () => vi.fn() }));

const tenantSvc = vi.hoisted(() => ({ getTenant: vi.fn() }));
vi.mock('@/hooks', () => ({ useTenant: () => tenantSvc }));

describe('TenantPage', () => {
  beforeEach(() => {
    tenantSvc.getTenant.mockReset();
    jwt.user = { tenantId: 't1', isTenantOwner: true };
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads the tenant through the SDK and shows its name and state', async () => {
    tenantSvc.getTenant.mockResolvedValue({
      success: true,
      data: { tenant: { id: 't1', name: 'acme', displayName: 'Acme Corp', state: 'active' } },
    });
    render(<TenantPage />);
    await screen.findByText('Acme Corp');
    screen.getByText('active');
    expect(tenantSvc.getTenant).toHaveBeenCalledWith('t1');
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('falls back to the tenant name when there is no display name', async () => {
    tenantSvc.getTenant.mockResolvedValue({
      success: true,
      data: { tenant: { id: 't1', name: 'acme', state: 'active' } },
    });
    render(<TenantPage />);
    await screen.findByText('acme');
  });

  it('shows the refusal and still shows the workspace ID', async () => {
    tenantSvc.getTenant.mockResolvedValue({
      success: false,
      error: { code: 'NOT_FOUND', message: 'tenant not found' },
    });
    render(<TenantPage />);
    await screen.findByText(/tenant not found/);
    screen.getByText('t1');
  });

  it('shows the empty state without a request when the user has no tenant', async () => {
    jwt.user = { tenantId: null, isTenantOwner: false };
    render(<TenantPage />);
    await waitFor(() => expect(screen.getByText('N/A')).toBeTruthy());
    expect(tenantSvc.getTenant).not.toHaveBeenCalled();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});
