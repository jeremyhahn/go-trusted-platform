'use client';

import { useDevice, useMutation } from 'trusted-platform-sdk';
import type { DeviceProfile, UseMutationResult } from 'trusted-platform-sdk';

/** DeviceIdentity is what an operator knows about a device: its EK serial, its MAC, or both. */
export interface DeviceIdentity {
  ekSerial: string;
  macAddress: string;
}

/**
 * useFindDeviceConfig asks the control plane which profile a device would
 * be delivered (GET /api/v1/device/profiles/find-config, resolution order
 * EK serial, exact MAC, then prefix match rules). Blank fields are trimmed
 * to empty so the SDK leaves them off the query. A device no profile
 * matches is a 404 refusal, which the caller reads from `error.status`.
 */
export function useFindDeviceConfig(): UseMutationResult<DeviceProfile | null, DeviceIdentity> {
  const deviceService = useDevice();
  return useMutation(({ ekSerial, macAddress }: DeviceIdentity) =>
    deviceService.findConfigForDevice({ ekSerial: ekSerial.trim(), macAddress: macAddress.trim() })
  );
}
