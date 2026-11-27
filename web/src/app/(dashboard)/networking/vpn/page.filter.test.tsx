import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import VPNPage from './page';

// #2070: the VPN page narrows the peers and posture policies to one tenant
// (tenant_id) and the status to one gateway (gateway_id), through the SDK
// arguments; Clear filters loads everything again.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/networking/vpn',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const VPN_OPS = [
  'GET /api/v1/vpn/status',
  'GET /api/v1/vpn/peers',
  'POST /api/v1/vpn/peers',
  'DELETE /api/v1/vpn/peers/{device_id}',
  'GET /api/v1/vpn/posture-policies',
  'GET /api/v1/vpn/posture-policies/{name}',
  'PUT /api/v1/vpn/posture-policies/{name}',
  'DELETE /api/v1/vpn/posture-policies/{name}',
] as const;

// The server's capabilities listing: every VPN op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = VPN_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: vpn' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(off: string[] = []): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(off),
    'GET /api/v1/vpn/status': ok({ gateways: [] }),
    'GET /api/v1/vpn/peers': ok({
      peers: [{ tenantId: 'acme', deviceId: 'laptop-1', zones: ['management'], enrolledAtUnix: '1760300000' }],
    }),
    'GET /api/v1/vpn/posture-policies': ok({
      policies: [{ tenantId: 'acme', name: 'corp', module: 'package vpn.posture\n', updatedAtUnix: '1760300000' }],
    }),
  };
}

// The stub's sent list keeps only the pathname; the query is read from the
// fetch mock's calls.
function sentUrls(): string[] {
  return vi.mocked(fetch).mock.calls.map(([input]) => (input instanceof Request ? input.url : String(input)));
}

async function loaded() {
  await screen.findByRole('button', { name: 'Revoke laptop-1' });
}

describe('VPNPage filters', () => {
  it('loads every tenant and every gateway with no filter', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<VPNPage />));
    await loaded();

    const urls = sentUrls();
    expect(urls.some((u) => u.includes('/api/v1/vpn/peers'))).toBe(true);
    expect(urls.filter((u) => u.includes('tenant_id=') || u.includes('gateway_id='))).toEqual([]);
  });

  it('applies a tenant filter to peers and posture policies', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<VPNPage />));
    await loaded();

    fireEvent.change(screen.getByRole('textbox', { name: 'Tenant' }), { target: { value: 'acme' } });
    expect(sentUrls().filter((u) => u.includes('tenant_id='))).toEqual([]);

    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
    await waitFor(() => {
      const urls = sentUrls();
      expect(urls.some((u) => u.endsWith('/api/v1/vpn/peers?tenant_id=acme'))).toBe(true);
      expect(urls.some((u) => u.endsWith('/api/v1/vpn/posture-policies?tenant_id=acme'))).toBe(true);
    });
    expect(sentUrls().filter((u) => u.includes('/api/v1/vpn/status') && u.includes('tenant_id'))).toEqual([]);
  });

  it('applies a gateway filter to the status', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<VPNPage />));
    await loaded();

    const gateway = screen.getByRole('textbox', { name: 'Gateway' });
    fireEvent.change(gateway, { target: { value: 'gw-1' } });
    fireEvent.submit(gateway.closest('form') as HTMLFormElement);
    await waitFor(() => {
      expect(sentUrls().some((u) => u.endsWith('/api/v1/vpn/status?gateway_id=gw-1'))).toBe(true);
    });
  });

  it('clearing the filters loads everything again', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<VPNPage />));
    await loaded();

    const tenant = screen.getByRole('textbox', { name: 'Tenant' }) as HTMLInputElement;
    fireEvent.change(tenant, { target: { value: 'acme' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
    await waitFor(() => {
      expect(sentUrls().some((u) => u.endsWith('/api/v1/vpn/peers?tenant_id=acme'))).toBe(true);
    });

    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(tenant.value).toBe('');
    await waitFor(() => {
      const peers = sentUrls().filter((u) => u.includes('/api/v1/vpn/peers'));
      expect(peers[peers.length - 1]).toMatch(/\/api\/v1\/vpn\/peers$/);
    });
  });
});
