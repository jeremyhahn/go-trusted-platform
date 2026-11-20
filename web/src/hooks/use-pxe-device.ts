'use client';

import { useCallback, useRef, useState } from 'react';
import { usePXE } from 'trusted-platform-sdk';
import type {
  ApiResponse,
  PXEDeviceInfo,
  PXEStatus,
  ProvisioningEvent,
  ProvisioningEventType,
  ProvisioningState,
} from 'trusted-platform-sdk';

/**
 * Drives the PXEService device operations (GetDevice, GetDeviceByMAC,
 * GetEvents, UpdateState, SetDeviceEnrolled, Authorize, Quarantine, Retry,
 * RemoveDevice) and the service start/stop for the PXE page (#2062).
 */

function unwrap<T>(response: ApiResponse<T>): T {
  if (!response.success || response.data === undefined) {
    throw new Error(response.error?.message ?? 'Request failed');
  }
  return response.data;
}

/** Throws when an operation answers HTTP 200 with a failed status. */
function checkStatus(data: { status?: PXEStatus }) {
  if (data.status && data.status.success === false) {
    throw new Error(data.status.message || 'Request failed');
  }
}

// The REST handlers serialize enums through protojson, which emits the proto
// enum name (PROVISIONING_STATE_FAILED); the page compares the short name.
const STATE_PREFIX = /^PROVISIONING_STATE_/;
const EVENT_PREFIX = /^PROVISIONING_EVENT_TYPE_/;

function shortState(s: unknown): ProvisioningState {
  return String(s ?? '').replace(STATE_PREFIX, '') as ProvisioningState;
}

function normalizeDevice(d: PXEDeviceInfo): PXEDeviceInfo {
  return { ...d, state: shortState(d.state) };
}

function normalizeEvent(e: ProvisioningEvent): ProvisioningEvent {
  return {
    ...e,
    eventType: String(e.eventType ?? '').replace(EVENT_PREFIX, '') as ProvisioningEventType,
    fromState: e.fromState === undefined ? undefined : shortState(e.fromState),
    toState: e.toState === undefined ? undefined : shortState(e.toState),
  };
}

/** States an operator may set by hand through UpdateState. */
export const SETTABLE_PXE_STATES: ProvisioningState[] = [
  'DISCOVERED',
  'BOOTING',
  'INSTALLING',
  'INSTALL_COMPLETE',
  'ENROLLING',
  'ENROLLED',
  'AUTHORIZING',
  'AUTHORIZED',
  'FAILED',
  'QUARANTINED',
];

export interface UsePXEDeviceResult {
  device: PXEDeviceInfo | null;
  events: ProvisioningEvent[];
  busy: boolean;
  error: string | null;
  notice: string | null;
  open: (deviceId: string) => Promise<void>;
  lookupByMAC: (mac: string) => Promise<void>;
  close: () => void;
  updateState: (state: ProvisioningState, reason?: string) => Promise<void>;
  setEnrolled: (certificateSerial: string) => Promise<void>;
  authorize: (targetVlan?: number) => Promise<void>;
  quarantine: (reason?: string) => Promise<void>;
  retry: () => Promise<void>;
  remove: () => Promise<void>;
}

export function usePXEDevice(): UsePXEDeviceResult {
  const service = usePXE();
  const [device, setDevice] = useState<PXEDeviceInfo | null>(null);
  const [events, setEvents] = useState<ProvisioningEvent[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Each selection takes a generation; a superseded one drops its result,
  // so a slow earlier lookup never becomes the target of an operation.
  const gen = useRef(0);

  const select = useCallback(
    async (fetchDevice: () => Promise<PXEDeviceInfo>) => {
      const mine = ++gen.current;
      const current = () => mine === gen.current;
      setBusy(true);
      setError(null);
      setNotice(null);
      setDevice(null);
      setEvents([]);
      try {
        const found = normalizeDevice(await fetchDevice());
        const evs = unwrap(await service.getEvents(found.id)).events ?? [];
        if (!current()) return;
        setDevice(found);
        setEvents(evs.map(normalizeEvent));
      } catch (err) {
        if (current()) setError(err instanceof Error ? err.message : 'Request failed');
      } finally {
        if (current()) setBusy(false);
      }
    },
    [service]
  );

  const open = useCallback(
    (deviceId: string) => select(async () => unwrap(await service.getDevice(deviceId.trim())).device),
    [select, service]
  );

  const lookupByMAC = useCallback(
    (mac: string) => select(async () => unwrap(await service.getDeviceByMAC(mac.trim())).device),
    [select, service]
  );

  const close = useCallback(() => {
    gen.current++;
    setDevice(null);
    setEvents([]);
    setError(null);
    setNotice(null);
  }, []);

  const run = useCallback(
    async (action: (d: PXEDeviceInfo) => Promise<string>, refresh = true) => {
      const d = device;
      setError(null);
      setNotice(null);
      if (!d) {
        setError('Open a device first');
        return;
      }
      const mine = gen.current;
      setBusy(true);
      try {
        const message = await action(d);
        if (refresh && mine === gen.current) {
          const fresh = normalizeDevice(unwrap(await service.getDevice(d.id)).device);
          const evs = unwrap(await service.getEvents(d.id)).events ?? [];
          if (mine === gen.current) {
            setDevice(fresh);
            setEvents(evs.map(normalizeEvent));
          }
        }
        setNotice(message);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Request failed');
      } finally {
        setBusy(false);
      }
    },
    [device, service]
  );

  const updateState = useCallback(
    (state: ProvisioningState, reason?: string) =>
      run(async (d) => {
        // protojson parses the enum by its proto name, not the short name.
        checkStatus(
          unwrap(
            await service.updateState({
              deviceId: d.id,
              state: `PROVISIONING_STATE_${state}` as ProvisioningState,
              reason: reason?.trim() || undefined,
            })
          )
        );
        return `State set to ${state}`;
      }),
    [run, service]
  );

  const setEnrolled = useCallback(
    (certificateSerial: string) =>
      run(async (d) => {
        const serial = certificateSerial.trim();
        if (!serial) throw new Error('Certificate serial is required');
        checkStatus(unwrap(await service.setDeviceEnrolled({ deviceId: d.id, certificateSerial: serial })));
        return 'Device marked enrolled';
      }),
    [run, service]
  );

  const authorize = useCallback(
    (targetVlan?: number) =>
      run(async (d) => {
        checkStatus(unwrap(await service.authorizeDevice({ deviceId: d.id, targetVlan })));
        return 'Device authorized';
      }),
    [run, service]
  );

  const quarantine = useCallback(
    (reason?: string) =>
      run(async (d) => {
        checkStatus(unwrap(await service.quarantineDevice({ deviceId: d.id, reason: reason?.trim() || undefined })));
        return 'Device quarantined';
      }),
    [run, service]
  );

  const retry = useCallback(
    () =>
      run(async (d) => {
        checkStatus(unwrap(await service.retryDevice(d.id)));
        return 'Provisioning retried';
      }),
    [run, service]
  );

  const remove = useCallback(
    () =>
      run(async (d) => {
        checkStatus(unwrap(await service.removeDevice(d.id)));
        gen.current++;
        setDevice(null);
        setEvents([]);
        return `Device ${d.macAddress} removed`;
      }, false),
    [run, service]
  );

  return {
    device,
    events,
    busy,
    error,
    notice,
    open,
    lookupByMAC,
    close,
    updateState,
    setEnrolled,
    authorize,
    quarantine,
    retry,
    remove,
  };
}

export interface UsePXEServiceControlResult {
  busy: boolean;
  error: string | null;
  notice: string | null;
  start: () => Promise<void>;
  stop: () => Promise<void>;
}

/** StartService and StopService; onChange runs after each success. */
export function usePXEServiceControl(onChange?: () => void): UsePXEServiceControlResult {
  const service = usePXE();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const run = useCallback(
    async (call: () => Promise<ApiResponse<{ status: PXEStatus }>>, message: string) => {
      setBusy(true);
      setError(null);
      setNotice(null);
      try {
        checkStatus(unwrap(await call()));
        setNotice(message);
        onChange?.();
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Request failed');
      } finally {
        setBusy(false);
      }
    },
    [onChange]
  );

  const start = useCallback(() => run(() => service.startService(), 'PXE service started'), [run, service]);
  const stop = useCallback(() => run(() => service.stopService(), 'PXE service stopped'), [run, service]);

  return { busy, error, notice, start, stop };
}
