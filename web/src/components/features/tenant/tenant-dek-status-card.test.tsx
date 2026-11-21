import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { TenantDEKStatusCard } from './tenant-dek-status-card';

// #2067: the data key card reads GetTenantDEKStatus
// (GET /api/v1/tenants/{id}/dek) on mount and on Refresh, and its
// Sync tenants button calls Sync (POST /api/v1/tenants/sync), telling a
// partial sync apart from a full one.

const DEK_PATH = 'GET /api/v1/tenants/t-1/dek';
const SYNC_PATH = 'POST /api/v1/tenants/sync';

function dek(overrides: Record<string, unknown> = {}): Answer {
  return ok({
    dekStatus: {
      tenantId: 't-1',
      version: '3',
      algorithm: 'AES-256-GCM',
      status: 'active',
      usageCount: '120',
      maxUsageCount: '1000',
      usagePercent: 12.4,
      needsRotation: false,
      ...overrides,
    },
  });
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

describe('TenantDEKStatusCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the DEK status on mount', async () => {
    const sent = stubControlPlane({ [DEK_PATH]: dek() });
    render(withControlPlane(<TenantDEKStatusCard tenantId="t-1" />));

    const status = (await screen.findByTestId('tenant-dek-status')).textContent ?? '';
    for (const want of ['3', 'AES-256-GCM', 'active', '120 / 1000', '12%']) {
      expect(status).toContain(want);
    }
    expect(screen.getByTestId('tenant-dek-rotation').textContent).toBe('Current');
    expect(sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/tenants/t-1/dek')).toHaveLength(1);
  });

  it('flags a key that needs rotation', async () => {
    stubControlPlane({ [DEK_PATH]: dek({ needsRotation: true }) });
    render(withControlPlane(<TenantDEKStatusCard tenantId="t-1" />));

    expect((await screen.findByTestId('tenant-dek-rotation')).textContent).toBe('Rotation due');
  });

  it('re-reads on Refresh', async () => {
    const sent = stubControlPlane({ [DEK_PATH]: dek() });
    render(withControlPlane(<TenantDEKStatusCard tenantId="t-1" />));
    await screen.findByTestId('tenant-dek-status');

    await click('Refresh');

    await waitFor(() =>
      expect(sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/tenants/t-1/dek')).toHaveLength(2)
    );
  });

  it('shows a refusal verbatim', async () => {
    stubControlPlane({ [DEK_PATH]: refused(404, 'tenant t-1 has no DEK') });
    render(withControlPlane(<TenantDEKStatusCard tenantId="t-1" />));

    expect((await screen.findByRole('alert')).textContent).toContain('tenant t-1 has no DEK');
  });

  it('syncs tenants', async () => {
    const sent = stubControlPlane({
      [DEK_PATH]: dek(),
      [SYNC_PATH]: ok({ status: { success: true, message: 'sync completed successfully' } }),
    });
    render(withControlPlane(<TenantDEKStatusCard tenantId="t-1" />));
    await screen.findByTestId('tenant-dek-status');

    await click('Sync tenants');

    const toast = await screen.findByText('Tenants synced: sync completed successfully');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(sent.filter((r) => r.method === 'POST' && r.path === '/api/v1/tenants/sync')).toHaveLength(1);
  });

  it('reports a partial sync', async () => {
    stubControlPlane({
      [DEK_PATH]: dek(),
      [SYNC_PATH]: ok({ status: { success: false, message: 'sync completed with errors: vault unreachable' } }),
    });
    render(withControlPlane(<TenantDEKStatusCard tenantId="t-1" />));
    await screen.findByTestId('tenant-dek-status');

    await click('Sync tenants');

    const toast = await screen.findByText('Sync incomplete: sync completed with errors: vault unreachable');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });
});
