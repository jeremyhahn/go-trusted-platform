import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import TenantQuotasPage from './page';

// #2067: the quotas page sets the tenant's limits through the SDK's
// TenantService.updateQuotas (PUT /tenants/{id}/quotas) and re-reads them,
// so the page shows what the control plane recorded; a refusal reaches the
// operator as a destructive toast and the editor stays open.

vi.mock('next/navigation', () => ({
  usePathname: () => '/tenant/quotas',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const authResult = { tenantId: 't-1', isLoading: false };

vi.mock('@/contexts/AuthContext', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/contexts/AuthContext')>()),
  useAuth: () => authResult,
}));

const QUOTAS_PATH = 'GET /api/v1/tenants/t-1/quotas';
const USAGE_PATH = 'GET /api/v1/tenants/t-1/usage';
const UPDATE_PATH = 'PUT /api/v1/tenants/t-1/quotas';

function storedQuotas(maxVms: number): Answer {
  return ok({
    tenantId: 't-1',
    compute: { maxVms, maxContainers: 30, maxVcpus: 48, maxMemoryMb: 65536 },
    network: { maxBridges: 6, maxPorts: 96, maxBandwidthMbps: 2500 },
    storage: { maxVolumesGb: 750, maxSnapshots: 40 },
  });
}

function storedUsage(): Answer {
  return ok({
    usage: {
      tenantId: 't-1',
      vms: 3,
      containers: 5,
      vcpus: 8,
      memoryMb: 8192,
      diskGb: 10,
      bridges: 1,
      ports: 4,
      bandwidthMbps: 100,
      volumes: 20,
      snapshots: 2,
      timestamp: '2026-11-21T00:00:00Z',
    },
  });
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

async function openEditor() {
  await screen.findByText('Quota Limits Reference');
  await click('Edit limits');
}

function setLimit(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function quotaReads(sent: Array<{ method: string; path: string }>): number {
  return sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/tenants/t-1/quotas').length;
}

describe('TenantQuotasPage UpdateQuotas', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads the limits through GET /tenants/{id}/quotas', async () => {
    const sent = stubControlPlane({ [QUOTAS_PATH]: storedQuotas(12), [USAGE_PATH]: storedUsage() });
    render(withControlPlane(<TenantQuotasPage />));

    await screen.findByText('Quota Limits Reference');
    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/tenants/t-1/quotas', body: undefined });
    expect(sent.some((r) => r.method === 'PUT')).toBe(false);
  });

  it('sends the edited limits through PUT /tenants/{id}/quotas and shows what it re-reads', async () => {
    const routes: Record<string, Answer> = {
      [QUOTAS_PATH]: storedQuotas(12),
      [USAGE_PATH]: storedUsage(),
      [UPDATE_PATH]: ok({ status: { success: true, message: 'quotas updated successfully' } }),
    };
    const sent = stubControlPlane(routes);
    render(withControlPlane(<TenantQuotasPage />));

    await openEditor();
    expect((screen.getByLabelText('Max VMs') as HTMLInputElement).value).toBe('12');
    setLimit('Max VMs', '37');
    routes[QUOTAS_PATH] = storedQuotas(37);
    await click('Save limits');

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'PUT',
        path: '/api/v1/tenants/t-1/quotas',
        body: {
          compute: { maxVms: 37, maxContainers: 30, maxVcpus: 48, maxMemoryMb: 65536 },
          network: { maxBridges: 6, maxPorts: 96, maxBandwidthMbps: 2500 },
          storage: { maxVolumesGb: 750, maxSnapshots: 40 },
        },
      })
    );
    const toast = await screen.findByText('Quotas updated: The new limits apply to this tenant.');
    expect(toast.getAttribute('data-variant')).toBe('default');

    const putAt = sent.findIndex((r) => r.method === 'PUT');
    await waitFor(() =>
      expect(
        sent.slice(putAt + 1).some((r) => r.method === 'GET' && r.path === '/api/v1/tenants/t-1/quotas')
      ).toBe(true)
    );
    await screen.findByText('37');
    expect(screen.queryByRole('button', { name: 'Save limits' })).toBeNull();
  });

  it('shows a refused write as a destructive toast and keeps the editor open', async () => {
    const sent = stubControlPlane({
      [QUOTAS_PATH]: storedQuotas(12),
      [USAGE_PATH]: storedUsage(),
      [UPDATE_PATH]: refused(403, 'quota update denied for tenant t-1'),
    });
    render(withControlPlane(<TenantQuotasPage />));

    await openEditor();
    const readsBefore = quotaReads(sent);
    // The toast store outlives a test; count the success toasts already there.
    const successToasts = () =>
      screen.queryAllByTestId('toast').filter((t) => t.textContent?.startsWith('Quotas updated')).length;
    const successBefore = successToasts();
    setLimit('Max VMs', '37');
    await click('Save limits');

    const toast = await screen.findByText('Quota update failed: quota update denied for tenant t-1');
    expect(toast.closest('[data-testid="toast"]')?.getAttribute('data-variant')).toBe('destructive');
    expect(successToasts()).toBe(successBefore);
    expect(screen.getByRole('button', { name: 'Save limits' })).toBeTruthy();
    expect(readsBefore).toBe(1);
    expect(quotaReads(sent)).toBe(1);
  });

  it('sends nothing for a limit that is not a whole number', async () => {
    const sent = stubControlPlane({
      [QUOTAS_PATH]: storedQuotas(12),
      [USAGE_PATH]: storedUsage(),
      [UPDATE_PATH]: ok({ status: { success: true, message: 'quotas updated successfully' } }),
    });
    render(withControlPlane(<TenantQuotasPage />));

    await openEditor();
    setLimit('Max ports', '-1');
    await click('Save limits');

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBe('Limits must be whole numbers, 0 or more.');
    expect(sent.some((r) => r.method === 'PUT')).toBe(false);
  });
});
