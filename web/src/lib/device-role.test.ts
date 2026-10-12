import { describe, expect, it } from "vitest";

import {
  ASSIGNABLE_DEVICE_ROLES,
  DEVICE_ROLES,
  UnknownDeviceRoleError,
  deviceRoleLabel,
  isDeviceRole,
  toDeviceRole,
} from "./device-role";

// #119: the console spelled roles as the gRPC enum (SERVER, LOAD_BALANCER),
// so it sent values the REST API rejects and labelled none of the values the
// API returns. These pin the console to the REST wire strings.

describe("device roles", () => {
  it("lists the ten REST wire strings", () => {
    expect(DEVICE_ROLES).toEqual([
      "unknown",
      "control-plane",
      "gateway",
      "worker",
      "server",
      "client",
      "workstation",
      "edge",
      "iot",
      "load-balancer",
    ]);
  });

  it("offers every role but unknown for assignment", () => {
    expect(ASSIGNABLE_DEVICE_ROLES).not.toContain("unknown");
    expect(ASSIGNABLE_DEVICE_ROLES).toHaveLength(DEVICE_ROLES.length - 1);
  });
});

describe("isDeviceRole", () => {
  it("accepts a wire string", () => {
    expect(isDeviceRole("load-balancer")).toBe(true);
  });

  it("rejects the enum spelling, a prototype key and a non-string", () => {
    expect(isDeviceRole("LOAD_BALANCER")).toBe(false);
    expect(isDeviceRole("toString")).toBe(false);
    expect(isDeviceRole(null)).toBe(false);
  });
});

describe("toDeviceRole", () => {
  it("returns a select value as a role", () => {
    expect(toDeviceRole("control-plane")).toBe("control-plane");
  });

  it("throws a typed error naming the value it rejects", () => {
    expect(() => toDeviceRole("SERVER")).toThrow(UnknownDeviceRoleError);

    const thrown = (() => {
      try {
        toDeviceRole(null);
      } catch (err) {
        return err;
      }
    })();
    expect(thrown).toBeInstanceOf(UnknownDeviceRoleError);
    expect((thrown as UnknownDeviceRoleError).role).toBe("null");
  });
});

describe("deviceRoleLabel", () => {
  it("names a role for display", () => {
    expect(deviceRoleLabel("iot")).toBe("IoT");
    expect(deviceRoleLabel("control-plane")).toBe("Control Plane");
  });

  it("shows a role it does not know as sent", () => {
    expect(deviceRoleLabel("mainframe")).toBe("mainframe");
  });
});
