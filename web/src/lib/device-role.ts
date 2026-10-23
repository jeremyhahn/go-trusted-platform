import type { DeviceRole } from "trusted-platform-sdk";

/**
 * Display name of every role the REST API sends, keyed by its wire string.
 * The exhaustive Record makes the compiler flag a role the SDK adds or drops
 * (#119).
 */
export const DEVICE_ROLE_LABELS: Record<DeviceRole, string> = {
  unknown: "Unknown",
  "control-plane": "Control Plane",
  gateway: "Gateway",
  worker: "Worker",
  server: "Server",
  client: "Client",
  workstation: "Workstation",
  edge: "Edge",
  iot: "IoT",
  "load-balancer": "Load Balancer",
};

/** Every role, in the order a role filter lists them. */
export const DEVICE_ROLES = Object.keys(DEVICE_ROLE_LABELS) as DeviceRole[];

/**
 * The roles an operator can give a new profile or template. `unknown` is what
 * the server reports for a missing role, not a role to choose.
 */
export const ASSIGNABLE_DEVICE_ROLES = DEVICE_ROLES.filter((role) => role !== "unknown");

/** UnknownDeviceRoleError names a value that is not one of the SDK's device roles. */
export class UnknownDeviceRoleError extends Error {
  readonly role: string;
  constructor(role: string) {
    super(`device role ${JSON.stringify(role)} is not in the SDK contract`);
    this.name = "UnknownDeviceRoleError";
    this.role = role;
  }
}

/** isDeviceRole narrows a value to the SDK DeviceRole union. */
export function isDeviceRole(value: unknown): value is DeviceRole {
  return typeof value === "string" && Object.hasOwn(DEVICE_ROLE_LABELS, value);
}

/** toDeviceRole converts a form or select value to a DeviceRole or throws a typed error. */
export function toDeviceRole(value: FormDataEntryValue | null): DeviceRole {
  if (!isDeviceRole(value)) throw new UnknownDeviceRoleError(String(value));
  return value;
}

/** deviceRoleLabel names a role for display, showing an unrecognised one as sent. */
export function deviceRoleLabel(role: string): string {
  return isDeviceRole(role) ? DEVICE_ROLE_LABELS[role] : role;
}
