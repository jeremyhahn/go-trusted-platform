import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { maskToModes, modesToMask, useGatewayMode } from './use-gateway-mode';

// #2051: the gateway mode hook sends SetGatewayMode as the proto GatewayMode
// bitmask and reads the gateway snapshots, all through the SDK GatewayService.

const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

function renderGatewayMode() {
  return renderHook(() => useGatewayMode(), { wrapper });
}

describe('useGatewayMode', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('sets the modes as a bitmask', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/gateway/mode': ok({
        status: { success: true, message: 'mode set' },
        gatewayStatus: { id: 'gw1', nodeId: 'n1', modes: 3, reputation: 1, uptimeSeconds: 10 },
      }),
    });
    const { result } = renderGatewayMode();

    let res: Awaited<ReturnType<typeof result.current.setModes>> | undefined;
    await act(async () => {
      res = await result.current.setModes(['OVERLAY', 'EDGE']);
    });

    expect(sent[0].method).toBe('POST');
    expect(sent[0].body).toEqual({ modes: 3 });
    expect(res?.data?.gatewayStatus?.modes).toBe(3);
  });

  it('surfaces a refused mode', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/gateway/mode': refused(400, 'invalid gateway mode'),
    });
    const { result } = renderGatewayMode();

    let res: Awaited<ReturnType<typeof result.current.setModes>> | undefined;
    await act(async () => {
      res = await result.current.setModes([]);
    });

    expect(sent[0].body).toEqual({ modes: 0 });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(400);
  });

  it('lists the snapshots', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/gateway/state': ok({
        gateways: [{ gateway_id: 'gw1', hostname: 'edge-a', mode: 'EDGE', reported_at: '2026-11-21T10:00:00Z' }],
        total: 1,
      }),
    });
    const { result } = renderGatewayMode();

    let res: Awaited<ReturnType<typeof result.current.listSnapshots>> | undefined;
    await act(async () => {
      res = await result.current.listSnapshots();
    });

    expect(sent[0].path).toBe('/api/v1/gateway/state');
    expect(res?.data?.gateways[0].gateway_id).toBe('gw1');
  });

  it('reads one snapshot', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/gateway/state/gw1': ok({ gateway_id: 'gw1', mode: 'OVERLAY', reported_at: '2026-11-21T10:00:00Z' }),
    });
    const { result } = renderGatewayMode();

    let res: Awaited<ReturnType<typeof result.current.getSnapshot>> | undefined;
    await act(async () => {
      res = await result.current.getSnapshot('gw1');
    });

    expect(sent[0].path).toBe('/api/v1/gateway/state/gw1');
    expect(res?.data?.mode).toBe('OVERLAY');
  });

  it('surfaces an unknown gateway', async () => {
    stubControlPlane({
      'GET /api/v1/gateway/state/nope': refused(404, 'gateway snapshot not found: nope'),
    });
    const { result } = renderGatewayMode();

    let res: Awaited<ReturnType<typeof result.current.getSnapshot>> | undefined;
    await act(async () => {
      res = await result.current.getSnapshot('nope');
    });

    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(404);
  });

  it('maps mode names and masks', () => {
    expect(modesToMask(['TRANSIT', 'OVERLAY', 'OVERLAY'])).toBe(5);
    expect(modesToMask([])).toBe(0);
    expect(maskToModes(6)).toEqual(['EDGE', 'TRANSIT']);
    expect(maskToModes(0)).toEqual([]);
    expect(maskToModes(8)).toEqual([]);
  });
});
