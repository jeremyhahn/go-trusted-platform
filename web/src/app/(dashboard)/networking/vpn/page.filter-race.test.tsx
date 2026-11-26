import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { withControlPlane } from '@/test/control-plane-fetch';
import VPNPage from './page';

// #2070: an answer for an older filter that arrives after a newer filter was applied never replaces the newer answer.

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
function caps() {
  const capabilities = VPN_OPS.map((op) => ({ op, kind: 'route', enabled: true }));
  return { capabilities, total: capabilities.length, enabled: capabilities.length };
}

// The control plane's success envelope, as web/src/test/control-plane-fetch.tsx answers it.
function okResponse(payload: unknown): Response {
  return new Response(JSON.stringify({ code: 200, success: true, payload }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

interface Pending {
  url: string;
  resolve: (body: unknown) => void;
  done: boolean;
}

const DEFERRED = ['/api/v1/vpn/peers', '/api/v1/vpn/posture-policies', '/api/v1/vpn/status'];

// deferredFetch answers the capabilities at once and holds every VPN read
// until the test resolves it.
function deferredFetch(): Pending[] {
  const pending: Pending[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      const path = new URL(url).pathname;
      if (path === '/api/v1/capabilities') {
        return Promise.resolve(okResponse(caps()));
      }
      if (DEFERRED.includes(path)) {
        return new Promise<Response>((resolve) => {
          const entry: Pending = {
            url,
            done: false,
            resolve: (body) => {
              entry.done = true;
              resolve(okResponse(body));
            },
          };
          pending.push(entry);
        });
      }
      return Promise.resolve(
        new Response(JSON.stringify({ code: 404, success: false, error: `no route for ${path}` }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        })
      );
    })
  );
  return pending;
}

function peer(deviceId: string, tenantId: string) {
  return { tenantId, deviceId, zones: ['management'], enrolledAtUnix: '1760300000' };
}

function policy(name: string, tenantId: string) {
  return { tenantId, name, module: 'package vpn.posture\n', updatedAtUnix: '1760300000' };
}

function gateway(gatewayId: string) {
  return {
    gatewayId,
    reportedAtUnix: '1760300000',
    reporting: true,
    running: true,
    admissions: '0',
    refusals: '0',
    lastRefusal: '',
    enrolledPeers: 0,
    leasesByDataPlane: {},
    leases: [],
    rejectedPeers: [],
    posturePolicyErrors: [],
    revocations: {},
    postureViolations: {},
    reattest: null,
  };
}

function find(pending: Pending[], match: (url: string) => boolean): Pending[] {
  return pending.filter((p) => !p.done && match(p.url));
}

async function resolveAll(entries: Pending[], body: unknown) {
  await act(async () => {
    for (const e of entries) {
      e.resolve(body);
    }
  });
}

// The first unfiltered loads answer with an empty page.
async function answerUnfiltered(pending: Pending[]) {
  await waitFor(() => expect(pending.length).toBeGreaterThanOrEqual(3));
  await act(async () => {
    for (const e of pending.filter((p) => !p.done)) {
      const path = new URL(e.url).pathname;
      if (path.endsWith('/status')) e.resolve({ gateways: [] });
      else if (path.endsWith('/peers')) e.resolve({ peers: [] });
      else e.resolve({ policies: [] });
    }
  });
}

function apply(input: HTMLInputElement, value: string) {
  fireEvent.change(input, { target: { value } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
}

describe('VPNPage filter answers', () => {
  it('keeps the newer tenant filter when the older peers answer arrives last', async () => {
    const pending = deferredFetch();
    const { container } = render(withControlPlane(<VPNPage />));
    await answerUnfiltered(pending);

    const tenant = container.querySelector('#vpn-filter-tenant') as HTMLInputElement;
    apply(tenant, 'acme');
    await waitFor(() => expect(find(pending, (u) => u.includes('tenant_id=acme')).length).toBe(2));
    apply(tenant, 'globex');
    await waitFor(() => expect(find(pending, (u) => u.includes('tenant_id=globex')).length).toBe(2));

    const globex = find(pending, (u) => u.includes('tenant_id=globex'));
    await resolveAll(globex.filter((p) => p.url.includes('/peers')), { peers: [peer('laptop-globex', 'globex')] });
    await resolveAll(globex.filter((p) => p.url.includes('/posture-policies')), {
      policies: [policy('globex-corp', 'globex')],
    });
    const acme = find(pending, (u) => u.includes('tenant_id=acme'));
    await resolveAll(acme.filter((p) => p.url.includes('/peers')), { peers: [peer('laptop-acme', 'acme')] });
    await resolveAll(acme.filter((p) => p.url.includes('/posture-policies')), {
      policies: [policy('acme-corp', 'acme')],
    });

    expect((await screen.findAllByText('laptop-globex')).length).toBeGreaterThan(0);
    await waitFor(() => expect(pending.every((p) => p.done)).toBe(true));
    expect(screen.queryByText('laptop-acme')).toBeNull();
    expect(screen.queryByText('acme-corp')).toBeNull();
  });

  it('keeps the newer gateway filter when the older status answer arrives last', async () => {
    const pending = deferredFetch();
    const { container } = render(withControlPlane(<VPNPage />));
    await answerUnfiltered(pending);

    const gatewayInput = container.querySelector('#vpn-filter-gateway') as HTMLInputElement;
    apply(gatewayInput, 'gw-a');
    await waitFor(() => expect(find(pending, (u) => u.includes('gateway_id=gw-a')).length).toBe(1));
    apply(gatewayInput, 'gw-b');
    await waitFor(() => expect(find(pending, (u) => u.includes('gateway_id=gw-b')).length).toBe(1));

    await resolveAll(find(pending, (u) => u.includes('gateway_id=gw-b')), { gateways: [gateway('gw-b')] });
    await resolveAll(find(pending, (u) => u.includes('gateway_id=gw-a')), { gateways: [gateway('gw-a')] });

    expect((await screen.findAllByText('gw-b')).length).toBeGreaterThan(0);
    await waitFor(() => expect(pending.every((p) => p.done)).toBe(true));
    expect(screen.queryByText('gw-a')).toBeNull();
  });
});
