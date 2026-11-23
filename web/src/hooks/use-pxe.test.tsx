import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { usePXE } from '@/hooks';

function renderPXE() {
  return renderHook(() => usePXE(), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('usePXE', () => {
  it('lists devices with the server filter names', async () => {
    stubControlPlane({
      'GET /api/v1/pxe/devices': ok({ devices: [{ id: 'd1', macAddress: '02:00:00:00:00:01' }] }),
    });
    const { result } = renderPXE();

    let res: Awaited<ReturnType<typeof result.current.listDevices>> | undefined;
    await act(async () => {
      res = await result.current.listDevices({ filter: { macAddress: '02:00:00', offset: 20, limit: 10 } });
    });

    // The stub records the path only; the query is on the URL fetch was given.
    const params = new URL(String(vi.mocked(fetch).mock.calls[0]?.[0])).searchParams;
    expect(params.get('mac_address')).toBe('02:00:00');
    expect(params.get('offset')).toBe('20');
    expect(params.get('limit')).toBe('10');
    expect(params.has('macAddress')).toBe(false);
    expect(params.has('page')).toBe(false);
    expect(res?.success).toBe(true);
    expect(res?.data?.devices[0]?.id).toBe('d1');
  });

  it('reads a device and its events by escaped id', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/pxe/devices/node%202': ok({ device: { id: 'node 2' } }),
      'GET /api/v1/pxe/devices/node%202/events': ok({ events: [] }),
    });
    const { result } = renderPXE();

    await act(async () => {
      await result.current.getDevice('node 2');
      await result.current.getEvents('node 2');
    });

    expect(sent.map((r) => `${r.method} ${r.path}`)).toEqual([
      'GET /api/v1/pxe/devices/node%202',
      'GET /api/v1/pxe/devices/node%202/events',
    ]);
  });

  it('reads a device by its escaped MAC', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/pxe/devices/mac/02%3A00%3A00%3A00%3A00%3A01': ok({ device: { id: 'd1' } }),
    });
    const { result } = renderPXE();

    await act(async () => {
      await result.current.getDeviceByMAC('02:00:00:00:00:01');
    });

    expect(sent).toHaveLength(1);
    expect(sent[0]?.method).toBe('GET');
    expect(sent[0]?.path).toBe('/api/v1/pxe/devices/mac/02%3A00%3A00%3A00%3A00%3A01');
  });

  it('sends each device write with the body the server decodes', async () => {
    const device = ok({ device: { id: 'd1' } });
    const sent = stubControlPlane({
      'POST /api/v1/pxe/devices/d1/authorize': device,
      'POST /api/v1/pxe/devices/d1/quarantine': device,
      'POST /api/v1/pxe/devices/d1/retry': device,
      'POST /api/v1/pxe/devices/d1/enrolled': device,
      'PUT /api/v1/pxe/devices/d1/state': device,
      'DELETE /api/v1/pxe/devices/d1': device,
    });
    const { result } = renderPXE();

    await act(async () => {
      await result.current.authorizeDevice({ deviceId: 'd1', targetVlan: 20 });
      await result.current.quarantineDevice({ deviceId: 'd1', reason: 'bad image' });
      await result.current.retryDevice('d1');
      await result.current.setDeviceEnrolled({ deviceId: 'd1', certificateSerial: '0A1B2C' });
      await result.current.updateState({ deviceId: 'd1', state: 'INSTALLING', reason: 'operator retry' });
      await result.current.removeDevice('d1');
    });

    expect(sent).toEqual([
      { method: 'POST', path: '/api/v1/pxe/devices/d1/authorize', body: { targetVlan: 20 } },
      { method: 'POST', path: '/api/v1/pxe/devices/d1/quarantine', body: { reason: 'bad image' } },
      { method: 'POST', path: '/api/v1/pxe/devices/d1/retry', body: {} },
      { method: 'POST', path: '/api/v1/pxe/devices/d1/enrolled', body: { certificateSerial: '0A1B2C' } },
      { method: 'PUT', path: '/api/v1/pxe/devices/d1/state', body: { state: 'PROVISIONING_STATE_INSTALLING', reason: 'operator retry' } },
      { method: 'DELETE', path: '/api/v1/pxe/devices/d1', body: undefined },
    ]);
  });

  it('reads the status and starts and stops the service', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/pxe/status': ok({ status: { running: true } }),
      'POST /api/v1/pxe/start': ok({}),
      'POST /api/v1/pxe/stop': ok({}),
    });
    const { result } = renderPXE();

    let status: Awaited<ReturnType<typeof result.current.getStatus>> | undefined;
    await act(async () => {
      status = await result.current.getStatus();
      await result.current.startService();
      await result.current.stopService();
    });

    expect(status?.data?.status.running).toBe(true);
    expect(sent).toEqual([
      { method: 'GET', path: '/api/v1/pxe/status', body: undefined },
      { method: 'POST', path: '/api/v1/pxe/start', body: {} },
      { method: 'POST', path: '/api/v1/pxe/stop', body: {} },
    ]);
  });

  it('surfaces a refusal', async () => {
    stubControlPlane({ 'POST /api/v1/pxe/start': refused(409, 'pxe: already running') });
    const { result } = renderPXE();

    let res: Awaited<ReturnType<typeof result.current.startService>> | undefined;
    await act(async () => {
      res = await result.current.startService();
    });

    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(409);
    expect(res?.error?.message).toContain('already running');
  });
});
