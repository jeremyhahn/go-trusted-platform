import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import {
  portStateBody,
  portStatePath,
  useSDNPortState,
  type GetPortStateResult,
  type PortAdminState,
  type SetPortStateResult,
} from './use-sdn-port-state';

// #2064: GetPort and SetPortState are served on
// GET|PUT /api/v1/sdn/bridges/{name}/ports/{port}/state; the hook drives the
// real SDK API client across the stubbed fetch.

const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

const STATE_PATH = '/api/v1/sdn/bridges/br0/ports/p1/state';

type Res<T> = { success: boolean; data?: T; error?: { status?: number } };

describe('useSDNPortState', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads the port state', async () => {
    const sent = stubControlPlane({
      [`GET ${STATE_PATH}`]: ok({ port: { id: 'p1', bridgeId: 'br0', status: { state: 'UP' } } }),
    });
    const { result } = renderHook(() => useSDNPortState('br0', 'p1'), { wrapper });

    let res: Res<GetPortStateResult> | undefined;
    await act(async () => {
      res = await result.current.getPort();
    });

    expect(res?.data?.port.id).toBe('p1');
    expect(sent).toEqual([{ method: 'GET', path: STATE_PATH, body: undefined }]);
  });

  it('sets a port down', async () => {
    const sent = stubControlPlane({
      [`PUT ${STATE_PATH}`]: ok({ status: { success: true, message: 'ok' }, port: { id: 'p1', bridgeId: 'br0' } }),
    });
    const { result } = renderHook(() => useSDNPortState('br0', 'p1'), { wrapper });

    let res: Res<SetPortStateResult> | undefined;
    await act(async () => {
      res = await result.current.setPortState({ adminState: 'down' });
    });

    expect(sent[0].body).toEqual({ adminState: 'down' });
    expect(res?.data?.status.success).toBe(true);
  });

  it('sends the rates when set', async () => {
    const sent = stubControlPlane({
      [`PUT ${STATE_PATH}`]: ok({ status: { success: true, message: 'ok' }, port: { id: 'p1', bridgeId: 'br0' } }),
    });
    const { result } = renderHook(() => useSDNPortState('br0', 'p1'), { wrapper });

    await act(async () => {
      await result.current.setPortState({ adminState: 'up', ingressRate: 1000.7, ingressBurst: 100, egressRate: 0 });
    });

    expect(sent[0].body).toEqual({ adminState: 'up', ingressRate: 1000, ingressBurst: 100 });
  });

  it('surfaces a refused state', async () => {
    stubControlPlane({
      [`PUT ${STATE_PATH}`]: refused(400, "admin_state must be 'up' or 'down'"),
    });
    const { result } = renderHook(() => useSDNPortState('br0', 'p1'), { wrapper });

    let res: Res<SetPortStateResult> | undefined;
    await act(async () => {
      res = await result.current.setPortState({ adminState: 'sideways' as PortAdminState });
    });

    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(400);
  });

  it('surfaces an unknown port', async () => {
    stubControlPlane({
      'GET /api/v1/sdn/bridges/br0/ports/nope/state': refused(404, 'port not found'),
    });
    const { result } = renderHook(() => useSDNPortState('br0', 'nope'), { wrapper });

    let res: Res<GetPortStateResult> | undefined;
    await act(async () => {
      res = await result.current.getPort();
    });

    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(404);
  });

  it('builds the path and body', () => {
    expect(portStatePath('br 0', 'p/1')).toBe('/v1/sdn/bridges/br%200/ports/p%2F1/state');
    expect(portStateBody({ adminState: 'up', egressRate: -5, egressBurst: Number.NaN })).toEqual({ adminState: 'up' });
  });
});
