import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { GatewaySnapshotsCard } from './gateway-snapshots-card';

// The card is gated; these cases test the reads with every op offered.
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));

// #2051: the gateway snapshots card lists the reported snapshots through the
// SDK GatewayService and opens one in the existing GatewaySnapshotDetail; a
// refusal is shown verbatim.

const LIST_PATH = 'GET /api/v1/gateway/state';

function baseRoutes(): Record<string, Answer> {
  return {
    [LIST_PATH]: ok({
      gateways: [
        { gateway_id: 'gw1', hostname: 'gw-a.example.test', mode: 'EDGE', reported_at: '2026-11-21T10:00:00Z' },
        { gateway_id: 'gw2', reported_at: '2026-11-21T10:05:00Z' },
      ],
      total: 2,
    }),
  };
}

async function clickButton(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

describe('GatewaySnapshotsCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('lists the reported snapshots', async () => {
    stubControlPlane(baseRoutes());
    render(withControlPlane(<GatewaySnapshotsCard />));

    await screen.findByText('gw-a.example.test');
    const rows = screen.getAllByTestId('gateway-snapshot-row');
    expect(rows).toHaveLength(2);
    const first = within(rows[0]);
    expect(first.getByText('gw1')).toBeDefined();
    expect(first.getByText('gw-a.example.test')).toBeDefined();
    expect(first.getByText('EDGE')).toBeDefined();
    expect(first.getByText('2026-11-21T10:00:00Z')).toBeDefined();
    const second = within(rows[1]);
    expect(second.getByText('gw2')).toBeDefined();
    expect(second.getAllByText('-').length).toBeGreaterThan(0);
    expect(screen.queryByTestId('gateway-snapshot-detail')).toBeNull();
  });

  it('shows an empty list', async () => {
    stubControlPlane({ [LIST_PATH]: ok({ gateways: [], total: 0 }) });
    render(withControlPlane(<GatewaySnapshotsCard />));

    expect(await screen.findByText('No gateway has reported state')).toBeDefined();
  });

  it('opens one snapshot in the detail and closes it', async () => {
    const sent = stubControlPlane({
      ...baseRoutes(),
      'GET /api/v1/gateway/state/gw1': ok({ gateway_id: 'gw1', mode: 'EDGE', reported_at: '2026-11-21T10:00:00Z' }),
    });
    render(withControlPlane(<GatewaySnapshotsCard />));

    await screen.findByText('gw-a.example.test');
    await clickButton('View gw1');

    const detail = await screen.findByTestId('gateway-snapshot-detail');
    expect(within(detail).getByText('Datapath — gw1')).toBeDefined();
    expect(sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/gateway/state/gw1')).toHaveLength(1);

    await clickButton('Close');
    expect(screen.queryByTestId('gateway-snapshot-detail')).toBeNull();
  });

  it('shows an unknown gateway verbatim', async () => {
    stubControlPlane({
      ...baseRoutes(),
      'GET /api/v1/gateway/state/gw2': refused(404, 'gateway/state: snapshot not found for gw2'),
    });
    render(withControlPlane(<GatewaySnapshotsCard />));

    await screen.findByText('gw-a.example.test');
    await clickButton('View gw2');

    const toast = await screen.findByText('Snapshot unavailable: gateway/state: snapshot not found for gw2');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByTestId('gateway-snapshot-detail')).toBeNull();
  });

  it('shows a list refusal verbatim', async () => {
    stubControlPlane({ [LIST_PATH]: refused(403, 'permission denied: sdn read') });
    render(withControlPlane(<GatewaySnapshotsCard />));

    const toast = await screen.findByText('Gateway snapshots unavailable: permission denied: sdn read');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });

  it('re-reads on Refresh', async () => {
    const sent = stubControlPlane(baseRoutes());
    render(withControlPlane(<GatewaySnapshotsCard />));

    await screen.findByText('gw-a.example.test');
    await clickButton('Refresh');

    await waitFor(() => {
      expect(sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/gateway/state')).toHaveLength(2);
    });
  });
});
