import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useDeviceTemplateActions } from "./use-device-template-actions";

type Fn = (arg: unknown) => Promise<unknown>;

const sdk = vi.hoisted(() => ({
  getTemplate: vi.fn(),
  findConfigForDevice: vi.fn(),
  assignProfileToDevice: vi.fn(),
  unassignProfileFromDevice: vi.fn(),
  captured: [] as unknown[],
}));

vi.mock("trusted-platform-sdk", () => ({
  useDevice: () => ({
    getTemplate: sdk.getTemplate,
    findConfigForDevice: sdk.findConfigForDevice,
    assignProfileToDevice: sdk.assignProfileToDevice,
    unassignProfileFromDevice: sdk.unassignProfileFromDevice,
  }),
  useMutation: (fn: unknown) => {
    sdk.captured.push(fn);
    return { fn };
  },
}));

function setup() {
  sdk.captured.length = 0;
  const { result } = renderHook(() => useDeviceTemplateActions());
  const fnOf = (m: unknown) => (m as { fn: Fn }).fn;
  return {
    getTemplate: fnOf(result.current.getTemplate),
    findConfig: fnOf(result.current.findConfig),
    assign: fnOf(result.current.assign),
    unassign: fnOf(result.current.unassign),
  };
}

// An id above 2^53: Number() would round it.
const BIG_ID = "18446744073709551615";

describe("useDeviceTemplateActions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sdk.getTemplate.mockResolvedValue({ data: { id: BIG_ID } });
    sdk.findConfigForDevice.mockResolvedValue({ data: null });
    sdk.assignProfileToDevice.mockResolvedValue({ data: { id: BIG_ID } });
    sdk.unassignProfileFromDevice.mockResolvedValue({ data: { id: BIG_ID } });
  });

  it("GetTemplate passes the decimal id string unchanged", async () => {
    await setup().getTemplate(BIG_ID);
    expect(sdk.getTemplate).toHaveBeenCalledWith(BIG_ID);
  });

  it("FindConfigForDevice passes the device identity", async () => {
    await setup().findConfig({ ekSerial: "ek-1", macAddress: "02:00:00:00:00:01" });
    expect(sdk.findConfigForDevice).toHaveBeenCalledWith({
      ekSerial: "ek-1",
      macAddress: "02:00:00:00:00:01",
    });
  });

  it("AssignProfileToDevice keeps a profile id above 2^53 exact", async () => {
    await setup().assign({ profileId: BIG_ID, ekSerial: "ek-1" });
    expect(sdk.assignProfileToDevice).toHaveBeenCalledWith({ profileId: BIG_ID, ekSerial: "ek-1" });
  });

  it("UnassignProfileFromDevice passes the profile id", async () => {
    await setup().unassign(BIG_ID);
    expect(sdk.unassignProfileFromDevice).toHaveBeenCalledWith(BIG_ID);
  });

  it("refuses a non-decimal template id without calling the server", async () => {
    await expect(setup().getTemplate("../1")).rejects.toThrow(/template id/i);
    expect(sdk.getTemplate).not.toHaveBeenCalled();
  });

  it("refuses a non-decimal profile id on assign without calling the server", async () => {
    await expect(setup().assign({ profileId: "1e3", ekSerial: "ek-1" })).rejects.toThrow(/profile id/i);
    expect(sdk.assignProfileToDevice).not.toHaveBeenCalled();
  });

  it("refuses an assign with no device identity without calling the server", async () => {
    await expect(setup().assign({ profileId: "7", ekSerial: " ", macAddress: "" })).rejects.toThrow(
      /ek serial or mac/i,
    );
    expect(sdk.assignProfileToDevice).not.toHaveBeenCalled();
  });

  it("refuses a non-decimal profile id on unassign without calling the server", async () => {
    await expect(setup().unassign("7/assign")).rejects.toThrow(/profile id/i);
    expect(sdk.unassignProfileFromDevice).not.toHaveBeenCalled();
  });

  it("refuses a config lookup with no device identity without calling the server", async () => {
    await expect(setup().findConfig({ ekSerial: "", macAddress: " " })).rejects.toThrow(/ek serial or mac/i);
    expect(sdk.findConfigForDevice).not.toHaveBeenCalled();
  });
});
