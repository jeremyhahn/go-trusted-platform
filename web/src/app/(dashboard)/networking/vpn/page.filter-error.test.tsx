import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import VPNPage from './page';

// #2070: a filtered read the server refuses (a tenant the caller may not
// read) keeps the header and the filter form above the error, so the
// operator can change the filter or clear it instead of retrying the same
// refused read.

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

// The server's capabilities listing: every VPN op enabled.
function caps(): Answer {
  const capabilities = VPN_OPS.map((op) => ({ op, kind: 'route', enabled: true }));
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.length });
}

function routes(): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    'GET /api/v1/vpn/status': ok({ gateways: [] }),
    'GET /api/v1/vpn/peers': ok({
      peers: [{ tenantId: 'acme', deviceId: 'laptop-1', zones: ['management'], enrolledAtUnix: '1760300000' }],
    }),
    'GET /api/v1/vpn/posture-policies': ok({
      policies: [{ tenantId: 'acme', name: 'corp', module: 'package vpn.posture\n', updatedAtUnix: '1760300000' }],
    }),
  };
}

// Answers from routes(), except a peers read for tenant other, which the
// server refuses.
function stubRefusingOtherTenant() {
  const table = routes();
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const method = (init?.method ?? 'GET').toUpperCase();
      const key = `${method} ${url.pathname}`;
      const answer =
        key === 'GET /api/v1/vpn/peers' && url.searchParams.get('tenant_id') === 'other'
          ? refused(403, 'tenant other is not yours')
          : (table[key] ?? refused(404, `no route for ${key}`));
      return new Response(JSON.stringify(answer.body), {
        status: answer.status,
        headers: { 'Content-Type': 'application/json' },
      });
    })
  );
}

function sentUrls(): string[] {
  return vi.mocked(fetch).mock.calls.map(([input]) => (input instanceof Request ? input.url : String(input)));
}

async function filterToOther() {
  stubRefusingOtherTenant();
  render(withControlPlane(<VPNPage />));
  await screen.findByRole('button', { name: 'Revoke laptop-1' });

  fireEvent.change(screen.getByRole('textbox', { name: 'Tenant' }), { target: { value: 'other' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));

  return screen.findByText('Error Loading VPN');
}

describe('VPNPage filter refused', () => {
  it('keeps the filter form when a filtered read is refused', async () => {
    const title = await filterToOther();

    // The toast carries the same message; read it from the alert itself.
    expect(title.parentElement?.textContent).toContain('tenant other is not yours');
    expect(screen.queryByTestId('vpn-filters')).not.toBeNull();
    expect((screen.getByRole('textbox', { name: 'Tenant' }) as HTMLInputElement).value).toBe('other');
  });

  it('Clear filters in the error state loads everything again', async () => {
    await filterToOther();

    fireEvent.click(screen.getAllByRole('button', { name: 'Clear filters' })[0]);

    await screen.findByRole('button', { name: 'Revoke laptop-1' });
    await waitFor(() => {
      const peers = sentUrls().filter((u) => new URL(u).pathname === '/api/v1/vpn/peers');
      expect(peers[peers.length - 1]).toMatch(/\/api\/v1\/vpn\/peers$/);
    });
    expect(screen.queryByText('Error Loading VPN')).toBeNull();
  });
});
