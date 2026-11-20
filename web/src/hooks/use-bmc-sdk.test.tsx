import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useBMC } from "./use-bmc";

/**
 * useBMC reads and drives a BMC profile through the SDK's BMCService
 * (`usePlatformClient().bmc`), never through a hand-written fetch (#2039).
 */

const PROFILE_ID = "7";

const DATA = {
  power: { state: "On" },
  bootDevice: { device: "pxe", persistent: false },
  virtualMedia: { mounted: false },
  sensors: [{ name: "Inlet Temp", value: 21, units: "C", status: "OK" }],
  systemInfo: {
    manufacturer: "HPE",
    product: "DL385 Gen10",
    serial_number: "SN-385",
    firmware_version: "2.80",
    bios_version: "A40",
    power_state: "On",
  },
  provisionStatus: {
    provision_id: "p-9",
    profile_id: PROFILE_ID,
    status: "pending",
    started_at: "2026-11-20T00:00:00Z",
    updated_at: "2026-11-20T00:00:00Z",
  },
  certificate: {
    subject: "CN=bmc-7",
    issuer: "CN=Platform CA",
    serial_number: "07",
    not_before: "2026-11-20T00:00:00Z",
    not_after: "2027-11-20T00:00:00Z",
    days_remaining: 365,
    fingerprint: "77:77",
  },
};

const ok = <T,>(data: T) => ({ success: true, data });
const refused = (message: string) => ({ success: false, error: { code: "FORBIDDEN", message } });

const bmc = vi.hoisted(() => ({
  getPowerStatus: vi.fn(),
  powerAction: vi.fn(),
  getBootDevice: vi.fn(),
  setBootDevice: vi.fn(),
  getVirtualMediaStatus: vi.fn(),
  mountISO: vi.fn(),
  unmountISO: vi.fn(),
  getSensors: vi.fn(),
  getSystemInfo: vi.fn(),
  provision: vi.fn(),
  getProvisionStatus: vi.fn(),
  getWebCertificate: vi.fn(),
}));

vi.mock("trusted-platform-sdk", () => ({
  usePlatformClient: () => ({ bmc }),
}));

const READS = [
  "getPowerStatus",
  "getBootDevice",
  "getVirtualMediaStatus",
  "getSensors",
  "getSystemInfo",
  "getProvisionStatus",
  "getWebCertificate",
] as const;

function answerReads() {
  bmc.getPowerStatus.mockResolvedValue(ok(DATA.power));
  bmc.getBootDevice.mockResolvedValue(ok(DATA.bootDevice));
  bmc.getVirtualMediaStatus.mockResolvedValue(ok(DATA.virtualMedia));
  bmc.getSensors.mockResolvedValue(ok(DATA.sensors));
  bmc.getSystemInfo.mockResolvedValue(ok(DATA.systemInfo));
  bmc.getProvisionStatus.mockResolvedValue(ok(DATA.provisionStatus));
  bmc.getWebCertificate.mockResolvedValue(ok(DATA.certificate));
}

async function loaded() {
  const hook = renderHook(() => useBMC(PROFILE_ID));
  await waitFor(() => expect(hook.result.current.isLoading).toBe(false));
  return hook;
}

describe("useBMC through the SDK BMCService", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    answerReads();
    for (const m of ["powerAction", "setBootDevice", "mountISO", "unmountISO", "provision"] as const) {
      bmc[m].mockResolvedValue(ok({ success: true }));
    }
    vi.stubGlobal(
      "fetch",
      vi.fn(() => {
        throw new Error("useBMC must not call fetch");
      })
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("loads every part through its SDK method with the profile ID", async () => {
    const { result } = await loaded();
    for (const m of READS) {
      expect(bmc[m]).toHaveBeenCalledWith(PROFILE_ID);
    }
    expect(fetch).not.toHaveBeenCalled();
    expect(result.current.errors).toEqual({});
    expect(result.current.power).toEqual(DATA.power);
    expect(result.current.bootDevice).toEqual(DATA.bootDevice);
    expect(result.current.virtualMedia).toEqual(DATA.virtualMedia);
    expect(result.current.sensors).toEqual(DATA.sensors);
    expect(result.current.systemInfo).toEqual(DATA.systemInfo);
    expect(result.current.provisionStatus).toEqual(DATA.provisionStatus);
    expect(result.current.certificate).toEqual(DATA.certificate);
  });

  it("turns a refused part into that part's error and still loads the rest", async () => {
    bmc.getSensors.mockResolvedValue(refused("sensors not supported"));
    bmc.getWebCertificate.mockResolvedValue(refused("missing scope bmc:cert"));
    const { result } = await loaded();
    expect(result.current.errors).toEqual({
      sensors: "sensors not supported",
      certificate: "missing scope bmc:cert",
    });
    expect(result.current.sensors).toBeNull();
    expect(result.current.certificate).toBeNull();
    expect(result.current.systemInfo).toEqual(DATA.systemInfo);
    expect(result.current.power).toEqual(DATA.power);
  });

  it("mountISO sends the iso_url to bmc.mountISO", async () => {
    const { result } = await loaded();
    await act(() => result.current.mountISO("x.iso"));
    expect(bmc.mountISO).toHaveBeenCalledWith(PROFILE_ID, { iso_url: "x.iso" });
  });

  it.each([
    ["unmountISO", (r: ReturnType<typeof useBMC>) => r.unmountISO(), [PROFILE_ID]],
    [
      "setBootDevice",
      (r: ReturnType<typeof useBMC>) => r.setBootDevice({ device: "disk", persistent: true }),
      [PROFILE_ID, { device: "disk", persistent: true }],
    ],
    ["provision", (r: ReturnType<typeof useBMC>) => r.provision(), [PROFILE_ID]],
    ["powerAction", (r: ReturnType<typeof useBMC>) => r.powerAction("off"), [PROFILE_ID, "off"]],
  ] as const)("%s calls its SDK method, then reloads", async (method, run, args) => {
    const { result } = await loaded();
    const readsBefore = bmc.getPowerStatus.mock.calls.length;
    await act(() => run(result.current));
    expect(bmc[method]).toHaveBeenCalledWith(...args);
    expect(bmc.getPowerStatus.mock.calls.length).toBeGreaterThan(readsBefore);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("a refused powerAction rejects with the server's message", async () => {
    const { result } = await loaded();
    bmc.powerAction.mockResolvedValue(refused("missing scope bmc:power"));
    await expect(act(() => result.current.powerAction("cycle"))).rejects.toThrow("missing scope bmc:power");
    expect(bmc.powerAction).toHaveBeenCalledWith(PROFILE_ID, "cycle");
  });
});
