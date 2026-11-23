import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { GatewaySnapshotsCard } from './gateway-snapshots-card';

const { off } = vi.hoisted(() => ({ off: new Set<string>() }));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: 'not-configured: gateway' } : { enabled: true },
  }),
}));

// #2051: the gateway snapshots card gates Refresh and View on the server's
// capabilities for the gateway state routes.

const LIST = 'GET /api/v1/gateway/state';
const GET = 'GET /api/v1/gateway/state/{id}';

function stub() {
  return stubControlPlane({
    [LIST]: ok({
      gateways: [{ gateway_id: 'gw-a', mode: 'EDGE', reported_at: '2026-11-21T10:00:00Z' }],
      total: 1,
    }),
    'GET /api/v1/gateway/state/gw-a': ok({ gateway_id: 'gw-a', mode: 'EDGE', reported_at: '2026-11-21T10:00:00Z' }),
  });
}

async function renderCard() {
  render(withControlPlane(<GatewaySnapshotsCard />));
  await waitFor(() => expect(screen.getAllByTestId('gateway-snapshot-row')).toHaveLength(1));
}

function button(name: string) {
  const card = screen.getByTestId('gateway-snapshots-card');
  const found = Array.from(card.querySelectorAll('button')).find(
    (b) => b.textContent?.trim() === name || b.getAttribute('aria-label') === name,
  );
  expect(found).toBeDefined();
  return found as HTMLButtonElement;
}

describe('GatewaySnapshotsCard capability gate', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    off.clear();
  });

  it('withholds Refresh when GET /api/v1/gateway/state is not offered', async () => {
    off.add(LIST);
    stub();
    await renderCard();

    const refresh = button('Refresh');
    expect(refresh.getAttribute('data-capability-op')).toBe(LIST);
    expect(refresh.getAttribute('data-capability-enabled')).toBe('false');
    expect(refresh.disabled).toBe(true);
    expect(refresh.getAttribute('title')).toBe('not-configured: gateway');
  });

  it('withholds View when GET /api/v1/gateway/state/{id} is not offered', async () => {
    off.add(GET);
    const sent = stub();
    await renderCard();

    const view = button('View gw-a');
    expect(view.getAttribute('data-capability-op')).toBe(GET);
    expect(view.getAttribute('data-capability-enabled')).toBe('false');
    expect(view.disabled).toBe(true);
    expect(view.getAttribute('title')).toBe('not-configured: gateway');

    await act(async () => {
      fireEvent.click(view);
    });
    expect(sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/gateway/state/gw-a')).toHaveLength(0);
  });

  it('offers both when the server offers them', async () => {
    stub();
    await renderCard();

    expect(button('Refresh').getAttribute('data-capability-enabled')).toBe('true');
    expect(button('View gw-a').getAttribute('data-capability-enabled')).toBe('true');
  });
});
