"use client";
import { useApi, useDevice, useMutation } from 'trusted-platform-sdk';
import type {
  ActivateDeviceRequest,
  ActivateDeviceResponse,
  Device,
  DeviceAttestRequest,
  DeviceAttestResponse,
  DeviceProfile,
  DeviceSelfServiceProfile,
  FindMatchingProfileRequest,
  UseApiResult,
  UseMutationResult,
} from 'trusted-platform-sdk';

import { useToast } from './use-toast';

/** A partial device update: the id plus only the fields that change. */
export type DeviceUpdate = Partial<Device> & { id: string };

/**
 * A profile update: the whole profile. The server replaces every field the
 * body omits, so send the profile last read with the changed fields.
 */
export type ProfileUpdate = DeviceProfile;

export interface DeviceAttestVariables {
  id: string;
  request: DeviceAttestRequest;
}

export interface DeviceLookup {
  deviceCount: UseApiResult<{ count: number }>;
  profileCount: UseApiResult<{ count: number }>;
  findDeviceBySerial: UseMutationResult<Device, string>;
  updateDevice: UseMutationResult<Device, DeviceUpdate>;
  attestDevice: UseMutationResult<DeviceAttestResponse, DeviceAttestVariables>;
  activateDevice: UseMutationResult<ActivateDeviceResponse, ActivateDeviceRequest>;
  getDeviceProfile: UseMutationResult<DeviceSelfServiceProfile, void>;
  findProfileByMAC: UseMutationResult<DeviceProfile, string>;
  findProfileBySerial: UseMutationResult<DeviceProfile, string>;
  findMatchingProfile: UseMutationResult<DeviceProfile, FindMatchingProfileRequest>;
  updateProfile: UseMutationResult<DeviceProfile, ProfileUpdate>;
}

/**
 * Device and profile lookups, counts, partial updates, activation and
 * attestation for the devices lookup page (#1743). Every failure raises a
 * destructive toast titled with the operation that failed.
 */
export function useDeviceLookup(): DeviceLookup {
  const deviceService = useDevice();
  const { toast } = useToast();

  const failed = (title: string) => ({
    onError: (error: { message: string }) => {
      toast({ title, description: error.message, variant: 'destructive' });
    },
  });
  const done = (title: string, description: string, refetch?: () => Promise<void>) => ({
    onSuccess: () => {
      toast({ title, description, variant: 'success' });
      void refetch?.();
    },
  });

  const deviceCount = useApi(() => deviceService.countDevices(), [], failed('Device count failed'));
  const profileCount = useApi(() => deviceService.countProfiles(), [], failed('Profile count failed'));

  const findDeviceBySerial = useMutation(
    (serial: string) => deviceService.findDeviceBySerial(serial),
    failed('Device lookup failed')
  );
  const updateDevice = useMutation(
    // The server applies only the fields present: a partial device is the request.
    (update: DeviceUpdate) => deviceService.updateDevice({ device: update as Device }),
    { ...failed('Device update failed'), ...done('Device updated', 'The device was saved') }
  );
  const attestDevice = useMutation(
    ({ id, request }: DeviceAttestVariables) => deviceService.attestDevice(id, request),
    failed('Attestation failed')
  );
  const activateDevice = useMutation(
    (request: ActivateDeviceRequest) => deviceService.activateDevice(request),
    // /device/activate-json resolves the admitted VLAN; it programs no switch.
    { ...failed('Activation failed'), ...done('Admitted VLAN resolved', 'The switch was not changed', deviceCount.refetch) }
  );
  const getDeviceProfile = useMutation<DeviceSelfServiceProfile, void>(
    () => deviceService.getDeviceProfile(),
    failed('Device profile failed')
  );
  const findProfileByMAC = useMutation(
    (mac: string) => deviceService.findProfileByMACAddress(mac),
    failed('Profile lookup failed')
  );
  const findProfileBySerial = useMutation(
    (serial: string) => deviceService.findProfileBySerial(serial),
    failed('Profile lookup failed')
  );
  const findMatchingProfile = useMutation(
    (request: FindMatchingProfileRequest) => deviceService.findMatchingProfile(request),
    failed('Profile match failed')
  );
  const updateProfile = useMutation(
    (update: ProfileUpdate) => deviceService.updateProfile({ profile: update }),
    { ...failed('Profile update failed'), ...done('Profile updated', 'The profile was saved', profileCount.refetch) }
  );

  return {
    deviceCount,
    profileCount,
    findDeviceBySerial,
    updateDevice,
    attestDevice,
    activateDevice,
    getDeviceProfile,
    findProfileByMAC,
    findProfileBySerial,
    findMatchingProfile,
    updateProfile,
  };
}
