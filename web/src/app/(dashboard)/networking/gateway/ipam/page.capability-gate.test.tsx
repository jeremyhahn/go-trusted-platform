import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import GatewayIPAMPage from './page';

// #2051: the gateway IP allocations page gates Refresh and Filter on the
// list op, Allocate on the POST op and Release on the DELETE op, each
// disabled with the server's reason when GET /api/v1/capabilities does not
// offer it.

const LIST = 'GET /api/v1/gateway/ipam/allocations';
const ALLOCATE = 'POST /api/v1/gateway/ipam/allocations';
const RELEASE = 'DELETE /api/v1/gateway/ipam/allocations';
const IPAM_OPS = [LIST, ALLOCATE, RELEASE] as const;
const REASON = 'not-configured: gateway';

// The server's capabilities listing: every gateway IPAM op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = IPAM_OPS.map((op) =>
    off.includes(op) ? { op, kind: 'route', enabled: false, reason: REASON } : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

const A1 = { ip: '192.0.2.10', poolId: 'pool-a', hostname: 'node-a', allocatedAt: '2026-11-20T00:00:00Z' };

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderPage(off: string[] = []) {
  stubControlPlane({
    'GET /api/v1/capabilities': caps(off),
    'GET /api/v1/gateway/ipam/allocations': ok({ allocations: [A1] }),
  });
  render(withControlPlane(<GatewayIPAMPage />));
}

const button = (name: string) => screen.getByRole('button', { name }) as HTMLButtonElement;

describe('GatewayIPAMPage capability gate', () => {
  it('disables Allocate with the server reason when POST /api/v1/gateway/ipam/allocations is not offered', async () => {
    renderPage([ALLOCATE]);
    await screen.findByText('192.0.2.10');
    await waitFor(() => {
      const allocate = button('Allocate');
      expect(allocate.getAttribute('data-capability-op')).toBe(ALLOCATE);
      expect(allocate.getAttribute('data-capability-enabled')).toBe('false');
      expect(allocate.disabled).toBe(true);
      expect(allocate.title).toBe(REASON);
      expect(button('Release 192.0.2.10').getAttribute('data-capability-enabled')).toBe('true');
    });
  });

  it('disables Release when DELETE /api/v1/gateway/ipam/allocations is not offered', async () => {
    renderPage([RELEASE]);
    await screen.findByText('192.0.2.10');
    await waitFor(() => {
      const release = button('Release 192.0.2.10');
      expect(release.getAttribute('data-capability-op')).toBe(RELEASE);
      expect(release.getAttribute('data-capability-enabled')).toBe('false');
      expect(release.disabled).toBe(true);
      expect(release.title).toBe(REASON);
      expect(button('Allocate').getAttribute('data-capability-enabled')).toBe('true');
    });
  });

  it('shows the not-enabled state and disables Refresh and Filter when GET /api/v1/gateway/ipam/allocations is not offered', async () => {
    renderPage([LIST]);
    const state = await screen.findByTestId('gateway-ipam-not-enabled');
    expect(state.textContent).toContain(REASON);
    await waitFor(() => {
      for (const name of ['Refresh', 'Filter']) {
        const b = button(name);
        expect(b.getAttribute('data-capability-op')).toBe(LIST);
        expect(b.getAttribute('data-capability-enabled')).toBe('false');
        expect(b.disabled).toBe(true);
      }
    });
  });

  it('enables every control when the server offers them', async () => {
    renderPage();
    await screen.findByText('192.0.2.10');
    await waitFor(() => {
      for (const name of ['Refresh', 'Filter', 'Allocate', 'Release 192.0.2.10']) {
        expect(button(name).getAttribute('data-capability-enabled')).toBe('true');
      }
    });
    expect(screen.queryByTestId('gateway-ipam-not-enabled')).toBeNull();
  });
});
