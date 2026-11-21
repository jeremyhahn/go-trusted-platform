import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import TenantQuotasPage from './page';

// #2067: the quotas page rotates the tenant's data encryption key through the
// SDK's TenantService.rotateDEK (POST /tenants/{id}/dek/rotate) behind an
// inline confirm; the new key version shows on success, and a refusal reaches
// the operator as a destructive toast with the confirm left open.

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
const ROTATE_PATH = 'POST /api/v1/tenants/t-1/dek/rotate';

const rotated = ok({ tenantId: 't-1', oldVersion: 3, newVersion: 4, timestamp: '2026-11-21T01:00:00Z' });

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

function posts(sent: Array<{ method: string }>): number {
  return sent.filter((r) => r.method === 'POST').length;
}

describe('TenantQuotasPage RotateTenantDEK', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('asks before it rotates and sends nothing when kept', async () => {
    const sent = stubControlPlane({
      [QUOTAS_PATH]: storedQuotas(12),
      [USAGE_PATH]: storedUsage(),
      [ROTATE_PATH]: rotated,
    });
    render(withControlPlane(<TenantQuotasPage />));

    await screen.findByText('Data Encryption Key');
    await click('Rotate data key');
    expect(screen.getByRole('group', { name: 'Confirm data key rotation' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Rotate now' })).toBeTruthy();
    expect(sent.some((r) => r.method === 'POST')).toBe(false);

    await click('Keep current key');
    expect(screen.queryByRole('button', { name: 'Rotate now' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Rotate data key' })).toBeTruthy();
    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });

  it('rotates through POST /tenants/{id}/dek/rotate and shows the new version', async () => {
    const sent = stubControlPlane({
      [QUOTAS_PATH]: storedQuotas(12),
      [USAGE_PATH]: storedUsage(),
      [ROTATE_PATH]: rotated,
    });
    render(withControlPlane(<TenantQuotasPage />));

    await screen.findByText('Data Encryption Key');
    await click('Rotate data key');
    await click('Rotate now');

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'POST',
        path: '/api/v1/tenants/t-1/dek/rotate',
        body: { background: false },
      })
    );
    const toast = await screen.findByText('Data key rotated: Version 3 replaced by version 4.');
    expect(toast.getAttribute('data-variant')).toBe('default');
    await screen.findByText('Current key version: 4');
    expect(screen.queryByRole('button', { name: 'Rotate now' })).toBeNull();
    expect(posts(sent)).toBe(1);
  });

  it('shows a refused rotation as a destructive toast and keeps the confirm open', async () => {
    const sent = stubControlPlane({
      [QUOTAS_PATH]: storedQuotas(12),
      [USAGE_PATH]: storedUsage(),
      [ROTATE_PATH]: refused(403, 'dek rotation denied for tenant t-1'),
    });
    render(withControlPlane(<TenantQuotasPage />));

    await screen.findByText('Data Encryption Key');
    await click('Rotate data key');
    await click('Rotate now');

    const toast = await screen.findByText('Data key rotation failed: dek rotation denied for tenant t-1');
    expect(toast.closest('[data-testid="toast"]')?.getAttribute('data-variant')).toBe('destructive');
    expect(screen.getByRole('button', { name: 'Rotate now' })).toBeTruthy();
    expect(screen.queryByText('Current key version: 4')).toBeNull();
    expect(posts(sent)).toBe(1);
  });

  it('sends one rotation when the committed POST loses its response', async () => {
    const sent: Array<{ method: string; path: string }> = [];
    const routes: Record<string, Answer> = {
      [QUOTAS_PATH]: storedQuotas(12),
      [USAGE_PATH]: storedUsage(),
    };
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(input instanceof Request ? input.url : String(input));
        const method = (init?.method ?? 'GET').toUpperCase();
        sent.push({ method, path: url.pathname });
        const key = `${method} ${url.pathname}`;
        if (key === ROTATE_PATH) {
          // The server committed the rotation; only its response is lost.
          throw new TypeError('Failed to fetch');
        }
        const answer = routes[key] ?? refused(404, `no route for ${key}`);
        return new Response(JSON.stringify(answer.body), {
          status: answer.status,
          headers: { 'Content-Type': 'application/json' },
        });
      })
    );
    render(withControlPlane(<TenantQuotasPage />));

    await screen.findByText('Data Encryption Key');
    await click('Rotate data key');
    await click('Rotate now');

    await waitFor(() => expect(posts(sent)).toBe(1));
    await act(async () => {
      await new Promise((r) => setTimeout(r, 1500));
    });
    expect(posts(sent)).toBe(1);

    const toast = await screen.findByText(/^Data key rotation failed:/);
    expect(toast.closest('[data-testid="toast"]')?.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByText('Current key version: 4')).toBeNull();
  }, 10_000);
});
