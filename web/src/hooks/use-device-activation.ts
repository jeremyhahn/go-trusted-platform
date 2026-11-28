'use client';

/**
 * Device activation hook: FindDeviceBySerial and ActivateDevice (#2048).
 *
 * The device lookup and the operator activation are made on the API client at
 * the served routes with the server's snake_case fields, until the SDK
 * DeviceService types match them (#2048).
 */

import { useMemo } from 'react';
import { usePlatformClient } from 'trusted-platform-sdk';

/** The bare DeviceResponse GET /devices/serial/{serial} answers. */
export interface FoundDevice {
  id?: string | number;
  serial?: string;
  model?: string;
  state?: string;
  switch_name?: string;
  switch_port?: string;
  last_heartbeat_at?: string;
}

/** What POST /device/activate-json answers. */
export interface ActivationResult {
  status?: string;
  vlan?: number;
  transitioned_at?: string;
}

export function useDeviceActivation() {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    return {
      findBySerial: (serial: string) =>
        api.get<FoundDevice>(`/v1/devices/serial/${encodeURIComponent(serial)}`),
      activate: (serial: string, macAddress?: string) =>
        api.post<ActivationResult>(
          '/v1/device/activate-json',
          macAddress ? { serial, mac_address: macAddress } : { serial }
        ),
    };
  }, [client]);
}
