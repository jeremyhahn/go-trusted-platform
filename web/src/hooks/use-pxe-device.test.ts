import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const service = {
  getDevice: vi.fn(),
  getDeviceByMAC: vi.fn(),
  getEvents: vi.fn(),
  updateState: vi.fn(),
  setDeviceEnrolled: vi.fn(),
  authorizeDevice: vi.fn(),
  quarantineDevice: vi.fn(),
  retryDevice: vi.fn(),
  removeDevice: vi.fn(),
  startService: vi.fn(),
  stopService: vi.fn(),
};

vi.mock('trusted-platform-sdk', () => ({
  usePXE: () => service,
}));

import { usePXEDevice, usePXEServiceControl } from './use-pxe-device';

const OK = { success: true, message: 'ok' };

function device(id: string, state: string, extra: Record<string, unknown> = {}) {
  return { id, macAddress: 'aa:bb:cc:dd:ee:ff', state, ...extra };
}

function ok<T>(data: T) {
  return { success: true, data };
}

function seed(state = 'PROVISIONING_STATE_DISCOVERED') {
  service.getDeviceByMAC.mockResolvedValue(ok({ device: device('pxe-1', state) }));
  service.getDevice.mockResolvedValue(ok({ device: device('pxe-1', state) }));
  service.getEvents.mockResolvedValue(
    ok({
      events: [
        {
          id: 'e1',
          deviceId: 'pxe-1',
          timestamp: '2026-11-20T00:00:00Z',
          eventType: 'PROVISIONING_EVENT_TYPE_DEVICE_DISCOVERED',
          toState: 'PROVISIONING_STATE_DISCOVERED',
        },
      ],
    })
  );
}

describe('usePXEDevice', () => {
  beforeEach(() => {
    for (const fn of Object.values(service)) fn.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it('looks a device up by MAC, strips the proto enum prefixes and loads its events', async () => {
    seed();
    const { result } = renderHook(() => usePXEDevice());

    await act(() => result.current.lookupByMAC(' aa:bb:cc:dd:ee:ff '));

    expect(service.getDeviceByMAC).toHaveBeenCalledWith('aa:bb:cc:dd:ee:ff');
    expect(service.getEvents).toHaveBeenCalledWith('pxe-1');
    expect(result.current.device?.state).toBe('DISCOVERED');
    expect(result.current.events).toHaveLength(1);
    expect(result.current.events[0].eventType).toBe('DEVICE_DISCOVERED');
    expect(result.current.events[0].toState).toBe('DISCOVERED');
    expect(result.current.error).toBeNull();
  });

  it('opens a device by ID through GetDevice', async () => {
    seed('PROVISIONING_STATE_ENROLLED');
    const { result } = renderHook(() => usePXEDevice());

    await act(() => result.current.open('pxe-1'));

    expect(service.getDevice).toHaveBeenCalledWith('pxe-1');
    expect(result.current.device?.state).toBe('ENROLLED');
  });

  it('a failed lookup clears the earlier device and reports the error', async () => {
    seed();
    const { result } = renderHook(() => usePXEDevice());
    await act(() => result.current.lookupByMAC('aa:bb:cc:dd:ee:ff'));
    expect(result.current.device).not.toBeNull();

    service.getDeviceByMAC.mockResolvedValue({ success: false, error: { message: 'device not found' } });
    await act(() => result.current.lookupByMAC('02:00:00:00:00:01'));

    expect(result.current.device).toBeNull();
    expect(result.current.events).toEqual([]);
    expect(result.current.error).toBe('device not found');
  });

  it('a superseded lookup that finishes last does not replace the latest device', async () => {
    let resolveFirst!: (v: unknown) => void;
    service.getDeviceByMAC.mockImplementation((mac: string) =>
      mac === 'first'
        ? new Promise((res) => {
            resolveFirst = res;
          })
        : Promise.resolve(ok({ device: device('pxe-2', 'PROVISIONING_STATE_BOOTING') }))
    );
    service.getEvents.mockResolvedValue(ok({ events: [] }));
    const { result } = renderHook(() => usePXEDevice());

    let first!: Promise<void>;
    act(() => {
      first = result.current.lookupByMAC('first');
    });
    await act(() => result.current.lookupByMAC('second'));
    expect(result.current.device?.id).toBe('pxe-2');

    await act(async () => {
      resolveFirst(ok({ device: device('pxe-1', 'PROVISIONING_STATE_DISCOVERED') }));
      await first;
    });
    expect(result.current.device?.id).toBe('pxe-2');
    expect(result.current.busy).toBe(false);
  });

  it('updateState sends the proto enum name the REST handler parses and refreshes the device', async () => {
    seed();
    service.updateState.mockResolvedValue(ok({ status: OK }));
    const { result } = renderHook(() => usePXEDevice());
    await act(() => result.current.lookupByMAC('aa:bb:cc:dd:ee:ff'));

    service.getDevice.mockResolvedValue(ok({ device: device('pxe-1', 'PROVISIONING_STATE_FAILED') }));
    await act(() => result.current.updateState('FAILED', 'disk'));

    expect(service.updateState).toHaveBeenCalledWith({
      deviceId: 'pxe-1',
      state: 'PROVISIONING_STATE_FAILED',
      reason: 'disk',
    });
    expect(result.current.device?.state).toBe('FAILED');
    expect(result.current.notice).toBe('State set to FAILED');
  });

  it('authorize, quarantine, retry and setEnrolled act on the open device', async () => {
    seed();
    service.authorizeDevice.mockResolvedValue(ok({ status: OK }));
    service.quarantineDevice.mockResolvedValue(ok({ status: OK }));
    service.retryDevice.mockResolvedValue(ok({ status: OK }));
    service.setDeviceEnrolled.mockResolvedValue(ok({ status: OK }));
    const { result } = renderHook(() => usePXEDevice());
    await act(() => result.current.lookupByMAC('aa:bb:cc:dd:ee:ff'));

    await act(() => result.current.quarantine('attestation failed'));
    expect(service.quarantineDevice).toHaveBeenCalledWith({ deviceId: 'pxe-1', reason: 'attestation failed' });
    expect(result.current.notice).toBe('Device quarantined');

    await act(() => result.current.retry());
    expect(service.retryDevice).toHaveBeenCalledWith('pxe-1');
    expect(result.current.notice).toBe('Provisioning retried');

    await act(() => result.current.setEnrolled('0a1b2c'));
    expect(service.setDeviceEnrolled).toHaveBeenCalledWith({ deviceId: 'pxe-1', certificateSerial: '0a1b2c' });

    await act(() => result.current.authorize(200));
    expect(service.authorizeDevice).toHaveBeenCalledWith({ deviceId: 'pxe-1', targetVlan: 200 });
    expect(result.current.notice).toBe('Device authorized');
  });

  it('an operation whose status reports failure surfaces the message', async () => {
    seed();
    service.retryDevice.mockResolvedValue(ok({ status: { success: false, message: 'not in FAILED state' } }));
    const { result } = renderHook(() => usePXEDevice());
    await act(() => result.current.lookupByMAC('aa:bb:cc:dd:ee:ff'));

    await act(() => result.current.retry());

    expect(result.current.error).toBe('not in FAILED state');
    expect(result.current.notice).toBeNull();
  });

  it('setEnrolled refuses an empty certificate serial without calling the server', async () => {
    seed();
    const { result } = renderHook(() => usePXEDevice());
    await act(() => result.current.lookupByMAC('aa:bb:cc:dd:ee:ff'));

    await act(() => result.current.setEnrolled('  '));

    expect(service.setDeviceEnrolled).not.toHaveBeenCalled();
    expect(result.current.error).toBe('Certificate serial is required');
  });

  it('remove deletes the open device and clears the selection', async () => {
    seed();
    service.removeDevice.mockResolvedValue(ok({ status: OK }));
    const { result } = renderHook(() => usePXEDevice());
    await act(() => result.current.lookupByMAC('aa:bb:cc:dd:ee:ff'));

    await act(() => result.current.remove());

    expect(service.removeDevice).toHaveBeenCalledWith('pxe-1');
    expect(result.current.device).toBeNull();
    expect(result.current.events).toEqual([]);
    expect(result.current.notice).toBe('Device aa:bb:cc:dd:ee:ff removed');
  });

  it('an action with no device open reports the error and calls nothing', async () => {
    const { result } = renderHook(() => usePXEDevice());

    await act(() => result.current.authorize());

    expect(service.authorizeDevice).not.toHaveBeenCalled();
    expect(result.current.error).toBe('Open a device first');
  });
});

describe('usePXEServiceControl', () => {
  beforeEach(() => {
    for (const fn of Object.values(service)) fn.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it('starts and stops the service and calls onChange after each', async () => {
    service.startService.mockResolvedValue(ok({ status: OK }));
    service.stopService.mockResolvedValue(ok({ status: OK }));
    const onChange = vi.fn();
    const { result } = renderHook(() => usePXEServiceControl(onChange));

    await act(() => result.current.stop());
    expect(service.stopService).toHaveBeenCalledTimes(1);
    expect(result.current.notice).toBe('PXE service stopped');

    await act(() => result.current.start());
    expect(service.startService).toHaveBeenCalledTimes(1);
    expect(result.current.notice).toBe('PXE service started');
    expect(onChange).toHaveBeenCalledTimes(2);
  });

  it('a refused start reports the server error and does not call onChange', async () => {
    service.startService.mockResolvedValue({ success: false, error: { message: 'permission denied' } });
    const onChange = vi.fn();
    const { result } = renderHook(() => usePXEServiceControl(onChange));

    await act(() => result.current.start());

    expect(result.current.error).toBe('permission denied');
    expect(onChange).not.toHaveBeenCalled();
  });
});
