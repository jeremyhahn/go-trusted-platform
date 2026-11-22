'use client';

/**
 * usePXEDeviceDetail reaches the PXE device detail operations through the
 * SDK client (`client.pxe`), never a hand-written fetch. The routes are
 * served under `/api/v1/pxe`:
 *
 *   - GetDevice:         GET  /devices/{id}
 *   - GetDeviceByMAC:    GET  /devices/mac/{mac}
 *   - GetEvents:         GET  /devices/{id}/events
 *   - UpdateState:       PUT  /devices/{id}/state
 *   - SetDeviceEnrolled: POST /devices/{id}/enrolled
 *   - StartService:      POST /start
 *   - StopService:       POST /stop
 *
 * UpdateState sends the full proto enum name (`PROVISIONING_STATE_*`): the
 * server decodes protojson with DiscardUnknown and silently drops an
 * unknown enum name, so a short name such as 'FAILED' would reach it as
 * UNSPECIFIED. States read back may come in either form; pxeStateLabel
 * renders both.
 *
 * StartService and StopService act on the whole PXE service, not on one
 * device.
 */

import { useMemo } from 'react';
import { usePXE, type ProvisioningState } from 'trusted-platform-sdk';

export const PROVISIONING_STATE_PREFIX = 'PROVISIONING_STATE_';

/** toWireState gives the full proto enum name for a short or full state name. */
export function toWireState(state: string): string {
  const upper = state.trim().toUpperCase();
  return upper.startsWith(PROVISIONING_STATE_PREFIX) ? upper : PROVISIONING_STATE_PREFIX + upper;
}

/** pxeStateLabel renders a short or full state name for an operator. */
export function pxeStateLabel(state?: string): string {
  if (!state) {
    return 'Unknown';
  }
  const short = state.startsWith(PROVISIONING_STATE_PREFIX)
    ? state.slice(PROVISIONING_STATE_PREFIX.length)
    : state;
  const words = short.replace(/_/g, ' ').toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export function usePXEDeviceDetail() {
  const pxe = usePXE();
  return useMemo(
    () => ({
      getDevice: (deviceId: string) => pxe.getDevice(deviceId),
      getDeviceByMAC: (mac: string) => pxe.getDeviceByMAC(mac.trim().toLowerCase()),
      getEvents: (deviceId: string) => pxe.getEvents(deviceId),
      updateState: (deviceId: string, state: string, reason?: string) =>
        pxe.updateState({ deviceId, state: toWireState(state) as ProvisioningState, reason }),
      setEnrolled: (deviceId: string, certificateSerial: string) =>
        pxe.setDeviceEnrolled({ deviceId, certificateSerial }),
      startService: () => pxe.startService(),
      stopService: () => pxe.stopService(),
    }),
    [pxe]
  );
}
