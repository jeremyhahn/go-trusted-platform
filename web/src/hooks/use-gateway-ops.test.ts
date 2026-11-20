import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

const seen = vi.hoisted(() => [] as Array<{ op: string; args: unknown[] }>);
const replies = vi.hoisted(() => new Map<string, unknown>());

const gateway = vi.hoisted(() => {
  const op =
    (name: string) =>
    (...args: unknown[]) => {
      seen.push({ op: name, args });
      return Promise.resolve(replies.get(name) ?? { success: true, data: {} });
    };
  return {
    setMode: op('setMode'),
    getState: op('getState'),
    listAdmittedVTEPs: op('listAdmittedVTEPs'),
    getAdmittedVTEP: op('getAdmittedVTEP'),
    getIPAMPool: op('getIPAMPool'),
    deleteIPAMPool: op('deleteIPAMPool'),
  };
});

vi.mock('trusted-platform-sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('trusted-platform-sdk')>()),
  useGateway: () => gateway,
}));

import { useGatewayOps } from './use-gateway-ops';

afterEach(() => {
  seen.length = 0;
  replies.clear();
});

describe('useGatewayOps', () => {
  it('sends each operation through the SDK gateway service', async () => {
    const { result } = renderHook(() => useGatewayOps());
    await act(async () => {
      await result.current.setMode(3);
      await result.current.getSnapshot('gw-1');
      await result.current.listAdmittedVTEPs('gw-1');
      await result.current.getAdmittedVTEP('192.0.2.10', 'gw-1');
      await result.current.getIPAMPool('pool-1');
      await result.current.deleteIPAMPool('pool-1');
    });
    expect(seen).toEqual([
      { op: 'setMode', args: [{ modes: 3 }] },
      { op: 'getState', args: ['gw-1'] },
      { op: 'listAdmittedVTEPs', args: ['gw-1'] },
      { op: 'getAdmittedVTEP', args: ['192.0.2.10', 'gw-1'] },
      { op: 'getIPAMPool', args: ['pool-1'] },
      { op: 'deleteIPAMPool', args: ['pool-1'] },
    ]);
  });

  it('returns the data of a successful call', async () => {
    replies.set('listAdmittedVTEPs', { success: true, data: { vteps: [{ vtep: '192.0.2.10' }] } });
    const { result } = renderHook(() => useGatewayOps());
    let out: unknown;
    await act(async () => {
      out = await result.current.listAdmittedVTEPs();
    });
    expect(out).toEqual({ ok: true, data: { vteps: [{ vtep: '192.0.2.10' }] } });
  });

  it('marks a 503 not-configured answer so the control can be gated', async () => {
    replies.set('setMode', {
      success: false,
      error: { code: 'SERVICE_UNAVAILABLE', message: 'gateway service not configured' },
    });
    const { result } = renderHook(() => useGatewayOps());
    let out: unknown;
    await act(async () => {
      out = await result.current.setMode(1);
    });
    expect(out).toEqual({ ok: false, error: 'gateway service not configured', notConfigured: true });
  });

  it('reports any other failure with the server message', async () => {
    replies.set('getIPAMPool', { success: false, error: { code: 'NOT_FOUND', message: 'pool not found' } });
    const { result } = renderHook(() => useGatewayOps());
    let out: unknown;
    await act(async () => {
      out = await result.current.getIPAMPool('nope');
    });
    expect(out).toEqual({ ok: false, error: 'pool not found', notConfigured: false });
  });

  it('turns a thrown call into a failed result', async () => {
    gateway.getState = () => Promise.reject(new Error('network down'));
    const { result } = renderHook(() => useGatewayOps());
    let out: unknown;
    await act(async () => {
      out = await result.current.getSnapshot('gw-1');
    });
    expect(out).toEqual({ ok: false, error: 'network down', notConfigured: false });
  });
});
