'use client';

/**
 * useDeviceProfileLookup finds a device profile by MAC address, by serial, or
 * by the MAC, serial and model it matches.
 *
 * The profile lookups are made on the API client at the served routes with
 * the server's snake_case fields, until the SDK DeviceService types match
 * them (#2048): the SDK expects the profile wrapped as `{ profile }`, which the
 * server does not send, and sends `macAddress`, which the server does not read.
 */

import { useMemo } from 'react';
import { usePlatformClient } from 'trusted-platform-sdk';

/** The profile the control plane answers (ProfileFullResponse), in its field names. */
export interface LookedUpProfile {
  id?: string | number;
  name?: string;
  model?: string;
  role?: string;
  zone?: string;
  mac_address?: string;
  ek_serial?: string;
  enrollment_network?: string;
  post_enrollment_network?: string;
  assigned?: boolean;
  assigned_at?: string;
}

/** The criteria FindMatchingProfile decodes; unset fields are left out. */
export interface ProfileMatchCriteria {
  mac_address?: string;
  serial?: string;
  model?: string;
}

export function useDeviceProfileLookup() {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    return {
      byMAC: (mac: string) =>
        api.get<LookedUpProfile>(`/v1/device/profiles/mac/${encodeURIComponent(mac)}`),
      bySerial: (serial: string) =>
        api.get<LookedUpProfile>(`/v1/device/profiles/serial/${encodeURIComponent(serial)}`),
      match: (criteria: ProfileMatchCriteria) =>
        api.post<LookedUpProfile>('/v1/device/profiles/match', criteria),
    };
  }, [client]);
}
