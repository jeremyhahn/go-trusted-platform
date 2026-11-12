"use client";

/**
 * Device template and profile-assignment actions the SDK's
 * `useDeviceTemplates` hook does not carry: fetching one template on demand
 * (GET /device/templates/{id}), looking up the config for a device
 * (GET /device/profiles/find-config) and binding a profile to a device or
 * releasing it (POST /device/profiles/{id}/assign and /unassign).
 */
import { useDevice, useMutation } from "trusted-platform-sdk";
import type {
  AssignProfileToDeviceRequest,
  DeviceProfile,
  DeviceTemplate,
  FindConfigForDeviceRequest,
} from "trusted-platform-sdk";

export function useDeviceTemplateActions() {
  const deviceService = useDevice();

  const getTemplate = useMutation<DeviceTemplate, string>((id) =>
    deviceService.getTemplate(id),
  );

  const findConfig = useMutation<DeviceProfile | null, FindConfigForDeviceRequest>(
    (request) => deviceService.findConfigForDevice(request),
  );

  const assign = useMutation<DeviceProfile, AssignProfileToDeviceRequest>((request) =>
    deviceService.assignProfileToDevice(request),
  );

  const unassign = useMutation<DeviceProfile, string>((profileId) =>
    deviceService.unassignProfileFromDevice(profileId),
  );

  return { getTemplate, findConfig, assign, unassign };
}
