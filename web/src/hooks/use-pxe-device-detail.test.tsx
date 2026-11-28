import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { pxeStateLabel, toWireState, usePXEDeviceDetail } from './use-pxe-device-detail';

// #2062: the PXE device detail hook reaches GetDevice, GetDeviceByMAC,
// GetEvents, UpdateState, SetDeviceEnrolled, StartService and StopService
// through the real SDK client, across the stubbed fetch boundary.

function renderDetail() {
  return renderHook(() => usePXEDeviceDetail(), {
    wrapper: ({ children }) => withControlPlane(children),
  });
}

describe('usePXEDeviceDetail', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads a device through GET /pxe/devices/{id}', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/pxe/devices/dev-1': ok({
        device: { id: 'dev-1', macAddress: 'aa:bb:cc:dd:ee:01', state: 'PROVISIONING_STATE_INSTALLING' },
      }),
    });
    const { result } = renderDetail();
    let res: Awaited<ReturnType<typeof result.current.getDevice>> | undefined;
    await act(async () => {
      res = await result.current.getDevice('dev-1');
    });
    expect(res?.data?.device.id).toBe('dev-1');
    expect(pxeStateLabel(res?.data?.device.state)).toBe('Installing');
    expect(sent).toEqual([{ method: 'GET', path: '/api/v1/pxe/devices/dev-1', body: undefined }]);
  });

  it('looks a device up by MAC', async () => {
    const key = 'GET /api/v1/pxe/devices/mac/aa%3Abb%3Acc%3Add%3Aee%3A01';
    const sent = stubControlPlane({
      [key]: ok({
        device: { id: 'dev-1', macAddress: 'aa:bb:cc:dd:ee:01', state: 'PROVISIONING_STATE_DISCOVERED' },
      }),
    });
    const { result } = renderDetail();
    let res: Awaited<ReturnType<typeof result.current.getDeviceByMAC>> | undefined;
    await act(async () => {
      res = await result.current.getDeviceByMAC(' AA:BB:CC:DD:EE:01 ');
    });
    expect(res?.data?.device.id).toBe('dev-1');
    expect(sent[0].path).toBe(key.slice('GET '.length));
  });

  it('reads the event timeline', async () => {
    stubControlPlane({
      'GET /api/v1/pxe/devices/dev-1/events': ok({
        events: [
          {
            id: 'e1',
            deviceId: 'dev-1',
            timestamp: '2026-11-20T10:00:00Z',
            eventType: 'PROVISIONING_EVENT_TYPE_PXE_BOOT_STARTED',
            fromState: 'PROVISIONING_STATE_BOOTING',
            toState: 'PROVISIONING_STATE_INSTALLING',
          },
        ],
      }),
    });
    const { result } = renderDetail();
    let res: Awaited<ReturnType<typeof result.current.getEvents>> | undefined;
    await act(async () => {
      res = await result.current.getEvents('dev-1');
    });
    expect(res?.data?.events).toHaveLength(1);
    expect(res?.data?.events[0].toState).toBe('PROVISIONING_STATE_INSTALLING');
  });

  it('sends the full proto state name', async () => {
    const sent = stubControlPlane({
      'PUT /api/v1/pxe/devices/dev-1/state': ok({
        status: { success: true, message: 'ok' },
        device: { id: 'dev-1', macAddress: 'aa:bb:cc:dd:ee:01', state: 'PROVISIONING_STATE_FAILED' },
      }),
    });
    const { result } = renderDetail();
    let res: Awaited<ReturnType<typeof result.current.updateState>> | undefined;
    await act(async () => {
      res = await result.current.updateState('dev-1', 'failed', 'disk error');
    });
    expect(res?.success).toBe(true);
    expect(sent).toEqual([
      {
        method: 'PUT',
        path: '/api/v1/pxe/devices/dev-1/state',
        body: { state: 'PROVISIONING_STATE_FAILED', reason: 'disk error' },
      },
    ]);
  });

  it('marks a device enrolled', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/pxe/devices/dev-1/enrolled': ok({ status: { success: true, message: 'ok' } }),
    });
    const { result } = renderDetail();
    let res: Awaited<ReturnType<typeof result.current.setEnrolled>> | undefined;
    await act(async () => {
      res = await result.current.setEnrolled('dev-1', '0a1b');
    });
    expect(res?.success).toBe(true);
    expect(sent[0].body).toEqual({ certificateSerial: '0a1b' });
  });

  it('starts and stops the PXE service, and surfaces a refusal', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/pxe/start': ok({ status: { success: true, message: 'started' } }),
      'POST /api/v1/pxe/stop': refused(409, 'pxe: service not running'),
    });
    const { result } = renderDetail();
    let started: Awaited<ReturnType<typeof result.current.startService>> | undefined;
    await act(async () => {
      started = await result.current.startService();
    });
    expect(started?.success).toBe(true);
    expect(sent[0].body).toEqual({});

    let stopped: Awaited<ReturnType<typeof result.current.stopService>> | undefined;
    await act(async () => {
      stopped = await result.current.stopService();
    });
    expect(stopped?.success).toBe(false);
    expect(stopped?.error?.status).toBe(409);
    expect(stopped?.error?.message).toContain('not running');
  });

  it('maps state names both ways', () => {
    expect(toWireState('FAILED')).toBe('PROVISIONING_STATE_FAILED');
    expect(toWireState(' failed ')).toBe('PROVISIONING_STATE_FAILED');
    expect(toWireState('PROVISIONING_STATE_ENROLLED')).toBe('PROVISIONING_STATE_ENROLLED');
    expect(pxeStateLabel('INSTALL_COMPLETE')).toBe('Install complete');
    expect(pxeStateLabel('PROVISIONING_STATE_INSTALL_COMPLETE')).toBe('Install complete');
    expect(pxeStateLabel(undefined)).toBe('Unknown');
  });
});
