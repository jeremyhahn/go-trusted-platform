import { describe, expect, it } from "vitest";
import {
  DEFAULT_ENROLLMENT_NETWORK,
  DEFAULT_FAILURE_NETWORK,
  DEFAULT_POST_ENROLLMENT_NETWORK,
} from "trusted-platform-sdk";
import type { DeviceProfile } from "trusted-platform-sdk";

import { networkPhaseRows, profileOverrides } from "./device-profile-networks";

// #1795: the profiles table lists a profile's open-keyed `networks` map with
// the roles each key is selected for, and the create-from-template pages post
// device-specific fields only inside `overrides` (#378). The helpers only pass
// strings through, so the inputs below are opaque tokens rather than addresses.

function profile(fields: Partial<DeviceProfile>): DeviceProfile {
  return fields as DeviceProfile;
}

describe("networkPhaseRows", () => {
  it("lists no rows for a profile without networks", () => {
    expect(networkPhaseRows(profile({}))).toEqual([]);
    expect(networkPhaseRows(profile({ networks: {} }))).toEqual([]);
  });

  it("marks the default keys with their roles when no selector is set", () => {
    const rows = networkPhaseRows(
      profile({
        networks: {
          [DEFAULT_ENROLLMENT_NETWORK]: { vlan: 10 },
          [DEFAULT_POST_ENROLLMENT_NETWORK]: { vlan: 20 },
          [DEFAULT_FAILURE_NETWORK]: { vlan: 30 },
        },
      }),
    );
    expect(rows).toEqual([
      { name: DEFAULT_ENROLLMENT_NETWORK, config: { vlan: 10 }, roles: ["enrollment"] },
      { name: DEFAULT_FAILURE_NETWORK, config: { vlan: 30 }, roles: ["failure"] },
      { name: DEFAULT_POST_ENROLLMENT_NETWORK, config: { vlan: 20 }, roles: ["post-enrollment"] },
    ]);
  });

  it("treats an empty selector as the default", () => {
    const rows = networkPhaseRows(
      profile({
        enrollment_network: "",
        networks: { [DEFAULT_ENROLLMENT_NETWORK]: {} },
      }),
    );
    expect(rows).toEqual([{ name: DEFAULT_ENROLLMENT_NETWORK, config: {}, roles: ["enrollment"] }]);
  });

  it("follows explicit selectors and lists unselected entries with no roles", () => {
    const rows = networkPhaseRows(
      profile({
        enrollment_network: "boot",
        post_enrollment_network: "prod",
        failure_network: "jail",
        networks: {
          prod: { static_ip: "ip-a" },
          boot: {},
          [DEFAULT_POST_ENROLLMENT_NETWORK]: {},
          jail: { vlan: 99 },
        },
      }),
    );
    expect(rows.map((r) => r.name)).toEqual(["boot", "jail", "prod", DEFAULT_POST_ENROLLMENT_NETWORK]);
    expect(rows.map((r) => r.roles)).toEqual([["enrollment"], ["failure"], ["post-enrollment"], []]);
    expect(rows[2].config).toEqual({ static_ip: "ip-a" });
  });

  it("gives one key every role it is selected for, in lifecycle order", () => {
    const rows = networkPhaseRows(
      profile({
        enrollment_network: "flat",
        post_enrollment_network: "flat",
        failure_network: "flat",
        networks: { flat: {} },
      }),
    );
    expect(rows).toEqual([
      { name: "flat", config: {}, roles: ["enrollment", "post-enrollment", "failure"] },
    ]);
  });

  it("lists no row for a selector naming a key the map lacks", () => {
    const rows = networkPhaseRows(profile({ enrollment_network: "missing", networks: { other: {} } }));
    expect(rows).toEqual([{ name: "other", config: {}, roles: [] }]);
  });

  it("matches selectors to keys exactly", () => {
    const rows = networkPhaseRows(profile({ enrollment_network: "Boot", networks: { boot: {} } }));
    expect(rows[0].roles).toEqual([]);
  });
});

describe("profileOverrides", () => {
  const blank = { staticIp: "", ekSerial: "", macAddress: "" };

  it("returns undefined when every input is blank", () => {
    expect(profileOverrides(blank)).toBeUndefined();
    expect(profileOverrides({ staticIp: "  ", ekSerial: "\t", macAddress: " \n" })).toBeUndefined();
  });

  it("writes a static IP under the post-enrollment key and selects it", () => {
    expect(profileOverrides({ ...blank, staticIp: "ip-a" })).toEqual({
      networks: { [DEFAULT_POST_ENROLLMENT_NETWORK]: { static_ip: "ip-a" } },
      post_enrollment_network: DEFAULT_POST_ENROLLMENT_NETWORK,
    });
  });

  it("binds the EK serial and the MAC address", () => {
    expect(profileOverrides({ ...blank, ekSerial: "ek-1" })).toEqual({ ek_serial: "ek-1" });
    expect(profileOverrides({ ...blank, macAddress: "mac-1" })).toEqual({ mac_address: "mac-1" });
  });

  it("trims every input", () => {
    expect(profileOverrides({ staticIp: " ip-a ", ekSerial: " ek-1\n", macAddress: "\tmac-1 " })).toEqual({
      networks: { [DEFAULT_POST_ENROLLMENT_NETWORK]: { static_ip: "ip-a" } },
      post_enrollment_network: DEFAULT_POST_ENROLLMENT_NETWORK,
      ek_serial: "ek-1",
      mac_address: "mac-1",
    });
  });

  it("leaves out blank inputs beside filled ones", () => {
    const overrides = profileOverrides({ staticIp: " ", ekSerial: "ek-1", macAddress: "" });
    expect(overrides).toEqual({ ek_serial: "ek-1" });
    expect(overrides).not.toHaveProperty("networks");
    expect(overrides).not.toHaveProperty("mac_address");
  });
});
