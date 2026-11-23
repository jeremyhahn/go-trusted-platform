import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { GatewayLBNAT64StatusCard } from './gateway-lb-nat64-status-card';

// #2052: the gateway page reads GetLBStatus and GetNAT64Status (the
// webservice routes) through the real SDK client; each Refresh sits behind
// the capability gate on its own route.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/networking/gateway',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const STATUS_OPS = ['GET /api/v1/gateway/lb/status', 'GET /api/v1/gateway/nat64/status'] as const;

// The server's capabilities listing: both status reads enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = STATUS_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: nat64' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

const LB = ok({ status: { active: true, vipCount: 2, healthyBackends: 3, totalBackends: 4, lastReconcile: null } });
const NAT64 = ok({
  status: {
    active: true,
    instancePresent: true,
    prefix: '64:ff9b::/96',
    instance: 'tp-nat64',
    sessions: '12',
    pool4Used: '3',
    moduleVersion: '4.1.10',
    flowCount: 2,
    lastReconcile: '2026-11-20T10:00:00Z',
    lastError: '',
  },
});

function routes(extra: Record<string, Answer> = {}): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    'GET /api/v1/gateway/lb/status': LB,
    'GET /api/v1/gateway/nat64/status': NAT64,
    ...extra,
  };
}

function count(sent: { method: string; path: string }[], method: string, path: string) {
  return sent.filter((r) => r.method === method && r.path === path).length;
}

describe('GatewayLBNAT64StatusCard', () => {
  it('shows the load-balancer summary and the NAT64 status', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<GatewayLBNAT64StatusCard />));

    await waitFor(() => expect(screen.getByTestId('lb-status').textContent).toContain('2 VIPs'));
    const lb = screen.getByTestId('lb-status').textContent ?? '';
    expect(lb).toContain('Active');
    expect(lb).toContain('3/4 backends healthy');
    expect(lb).toContain('never');

    await waitFor(() => expect(screen.getByTestId('nat64-status').textContent).toContain('64:ff9b::/96'));
    const nat64 = screen.getByTestId('nat64-status').textContent ?? '';
    expect(nat64).toContain('tp-nat64');
    expect(nat64).toContain('12 sessions');
    expect(nat64).toContain('3 pool4 used');
    expect(nat64).toContain('2 flows');
  });

  it('refresh re-reads only that status', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<GatewayLBNAT64StatusCard />));

    await waitFor(() => expect(screen.getByTestId('lb-status').textContent).toContain('2 VIPs'));
    await waitFor(() => expect(screen.getByTestId('nat64-status').textContent).toContain('tp-nat64'));
    const refresh = screen.getByTestId('lb-status-refresh') as HTMLButtonElement;
    await waitFor(() => {
      expect(refresh.getAttribute('data-capability-enabled')).toBe('true');
      expect(refresh.disabled).toBe(false);
    });

    await act(async () => {
      fireEvent.click(refresh);
    });

    await waitFor(() => expect(count(sent, 'GET', '/api/v1/gateway/lb/status')).toBe(2));
    expect(count(sent, 'GET', '/api/v1/gateway/nat64/status')).toBe(1);
    expect(sent.filter((r) => r.method !== 'GET')).toEqual([]);
  });

  it('a refused read shows the server message', async () => {
    stubControlPlane(routes({ 'GET /api/v1/gateway/nat64/status': refused(409, 'nat64: kernel module missing') }));
    render(withControlPlane(<GatewayLBNAT64StatusCard />));

    expect((await screen.findByTestId('nat64-status-error')).textContent).toContain('kernel module missing');
    await waitFor(() => expect(screen.getByTestId('lb-status').textContent).toContain('2 VIPs'));
  });

  it('withholds the refresh the server does not offer', async () => {
    stubControlPlane(routes({ 'GET /api/v1/capabilities': caps(['GET /api/v1/gateway/nat64/status']) }));
    render(withControlPlane(<GatewayLBNAT64StatusCard />));

    await waitFor(() => {
      const nat64 = screen.getByTestId('nat64-status-refresh') as HTMLButtonElement;
      expect(nat64.getAttribute('data-capability-enabled')).toBe('false');
      expect(nat64.disabled).toBe(true);
      expect(nat64.title).toBe('not-configured: nat64');
    });
    await waitFor(() => {
      const lb = screen.getByTestId('lb-status-refresh') as HTMLButtonElement;
      expect(lb.getAttribute('data-capability-enabled')).toBe('true');
      expect(lb.disabled).toBe(false);
    });
  });
});
