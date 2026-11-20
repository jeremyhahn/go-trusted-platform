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

  const getTemplate = useMutation<DeviceTemplate, string>(async (id) =>
    deviceService.getTemplate(requireDecimalId(id, "template id")),
  );

  const findConfig = useMutation<DeviceProfile | null, FindConfigForDeviceRequest>(
    async (request) => {
      requireIdentity(request.ekSerial, request.macAddress);
      return deviceService.findConfigForDevice(request);
    },
  );

  const assign = useMutation<DeviceProfile, AssignProfileToDeviceRequest>(async (request) => {
    requireDecimalId(request.profileId, "profile id");
    requireIdentity(request.ekSerial, request.macAddress);
    return deviceService.assignProfileToDevice(request);
  });

  const unassign = useMutation<DeviceProfile, string>(async (profileId) =>
    deviceService.unassignProfileFromDevice(requireDecimalId(profileId, "profile id")),
  );

  return { getTemplate, findConfig, assign, unassign };
}

/**
 * Ids are decimal strings (generated ids exceed 2^53). Anything else would
 * build a different route (`7/assign`, `../1`) or a rounded id, so it is
 * refused before a request is made. Mutation functions are async, so a
 * throw here rejects the mutation.
 */
function requireDecimalId(id: string, what: string): string {
  if (!/^[0-9]+$/.test(String(id))) {
    throw new Error(`Invalid ${what} "${id}": expected a decimal number`);
  }
  return String(id);
}

/** FindConfigForDevice and AssignProfileToDevice key on the device's EK serial or MAC. */
function requireIdentity(ekSerial?: string, macAddress?: string): void {
  if ((ekSerial ?? "").trim() === "" && (macAddress ?? "").trim() === "") {
    throw new Error("An EK serial or MAC address is required to identify the device");
  }
}
