'use client';

import { useDevice, useMutation } from 'trusted-platform-sdk';
import type { DeviceProfile, UseMutationResult } from 'trusted-platform-sdk';

/**
 * ProfileAssignmentInput is what an operator types to bind a device profile
 * to a device: the profile's id plus at least one of the device's id, its EK
 * serial or its MAC address, and optionally its EK certificate (PEM) to
 * prestage.
 */
export interface ProfileAssignmentInput {
  profileId: string;
  ekSerial?: string;
  macAddress?: string;
  deviceId?: string;
  ekCert?: string;
}

export interface UseProfileAssignmentResult {
  assign: UseMutationResult<DeviceProfile, ProfileAssignmentInput>;
  unassign: UseMutationResult<DeviceProfile, string>;
}

/** blankToUndefined trims a field and leaves a blank one out of the request. */
function blankToUndefined(value: string | undefined): string | undefined {
  const trimmed = value?.trim() ?? '';
  return trimmed === '' ? undefined : trimmed;
}

/**
 * sdkProfileId turns a profile id (a string on the wire) into the number
 * the SDK takes, refusing one a JavaScript number cannot carry exactly: an
 * id past 2^53 would otherwise reach a different profile.
 */
function sdkProfileId(profileId: string): number {
  const trimmed = profileId.trim();
  const id = Number(trimmed);
  if (trimmed === '' || !/^[0-9]+$/.test(trimmed) || !Number.isSafeInteger(id)) {
    throw new Error(`profile id ${JSON.stringify(trimmed)} is not a whole number the client can send exactly`);
  }
  return id;
}

/**
 * useProfileAssignment assigns a device profile to a device
 * (POST /api/v1/device/profiles/{id}/assign) and unassigns it
 * (POST /api/v1/device/profiles/{id}/unassign) through the SDK's
 * DeviceService. Fields are trimmed and blank ones left off; an assignment
 * with no device id, EK serial or MAC address, or a profile id the SDK's
 * number cannot carry, is refused before any request is sent.
 */
export function useProfileAssignment(): UseProfileAssignmentResult {
  const deviceService = useDevice();

  const assign = useMutation(async (input: ProfileAssignmentInput) => {
    const profileId = sdkProfileId(input.profileId);
    const deviceId = blankToUndefined(input.deviceId);
    const ekSerial = blankToUndefined(input.ekSerial);
    const macAddress = blankToUndefined(input.macAddress);
    const ekCert = blankToUndefined(input.ekCert);
    if (deviceId === undefined && ekSerial === undefined && macAddress === undefined) {
      throw new Error('a device identity is required: a device ID, an EK serial or a MAC address');
    }
    return deviceService.assignProfileToDevice({ profileId, deviceId, ekSerial, macAddress, ekCert });
  });

  const unassign = useMutation(async (profileId: string) =>
    deviceService.unassignProfileFromDevice(sdkProfileId(profileId))
  );

  return { assign, unassign };
}
