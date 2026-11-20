import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useBMC } from "./use-bmc";

/**
 * useBMC reads and drives one BMC profile through the SDK's
 * PlatformClient.bmc (BMCService), never a direct fetch, so the SDK's base
 * URL, auth interceptors and transport apply (#1675 F27). It reads each part
 * in the server's JSON shapes (pkg/webservice/v1/bmc/types.go,
 * pkg/bmc/types.go) and mounts an ISO with the iso_url the handler requires
 * (#1736).
 */

const bmc = {
  getPowerStatus: vi.fn(),
  getBootDevice: vi.fn(),
  getVirtualMediaStatus: vi.fn(),
  getSensors: vi.fn(),
  getSystemInfo: vi.fn(),
  getProvisionStatus: vi.fn(),
  getWebCertificate: vi.fn(),
  setBootDevice: vi.fn(),
  mountISO: vi.fn(),
  unmountISO: vi.fn(),
  provision: vi.fn(),
};

// One stable client: a new object per render would re-run the hook's effects.
const client = { bmc };

vi.mock("trusted-platform-sdk", () => ({
  usePlatformClient: () => client,
}));

/** The numeric device-profile ID the server routes take. */
const PROFILE_ID = "1";

const PAYLOADS: Record<string, unknown> = {
  power: { state: "On" },
  "boot-device": { device: "disk" },
  "virtual-media": { mounted: true, image_url: "rescue.iso", media_type: "CD" },
  sensors: [{ name: "CPU1 Temp", value: 42, units: "C", status: "OK" }],
  "system-info": {
    manufacturer: "Dell Inc.",
    product: "PowerEdge R640",
    serial_number: "SN-R640-01",
    firmware_version: "7.00.00",
    bios_version: "2.19.1",
    power_state: "On",
  },
  provision: {
    provision_id: "p-1",
    profile_id: PROFILE_ID,
    status: "installing",
    started_at: "2026-11-12T00:00:00Z",
    updated_at: "2026-11-12T00:05:00Z",
  },
  cert: {
    subject: "CN=bmc-1",
    issuer: "CN=Platform CA",
    serial_number: "01",
    not_before: "2026-11-12T00:00:00Z",
    not_after: "2027-11-12T00:00:00Z",
    days_remaining: 365,
    fingerprint: "AA:BB:CC",
  },
};

const ok = (data: unknown) => ({ success: true, data });

describe("useBMC", () => {
  beforeEach(() => {
    bmc.getPowerStatus.mockResolvedValue(ok(PAYLOADS.power));
    bmc.getBootDevice.mockResolvedValue(ok(PAYLOADS["boot-device"]));
    bmc.getVirtualMediaStatus.mockResolvedValue(ok(PAYLOADS["virtual-media"]));
    bmc.getSensors.mockResolvedValue(ok(PAYLOADS.sensors));
    bmc.getSystemInfo.mockResolvedValue(ok(PAYLOADS["system-info"]));
    bmc.getProvisionStatus.mockResolvedValue(ok(PAYLOADS.provision));
    bmc.getWebCertificate.mockResolvedValue(ok(PAYLOADS.cert));
    for (const write of [bmc.setBootDevice, bmc.mountISO, bmc.unmountISO, bmc.provision]) {
      write.mockResolvedValue(ok({ success: true }));
    }
    vi.stubGlobal(
      "fetch",
      vi.fn(() => {
        throw new Error("the BMC hooks must not call fetch");
      })
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("reads every part through client.bmc", async () => {
    const { result } = renderHook(() => useBMC(PROFILE_ID));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.errors).toEqual({});
    expect(result.current.sensors?.[0].value).toBe(42);
    expect(result.current.virtualMedia?.mounted).toBe(true);
    expect(result.current.virtualMedia?.image_url).toBe("rescue.iso");
    expect(result.current.systemInfo?.product).toBe("PowerEdge R640");
    expect(result.current.provisionStatus?.status).toBe("installing");
    expect(result.current.certificate?.fingerprint).toBe("AA:BB:CC");
    for (const read of [
      bmc.getPowerStatus,
      bmc.getBootDevice,
      bmc.getVirtualMediaStatus,
      bmc.getSensors,
      bmc.getSystemInfo,
      bmc.getProvisionStatus,
      bmc.getWebCertificate,
    ]) {
      expect(read).toHaveBeenCalledWith("1");
    }
    expect(fetch).not.toHaveBeenCalled();
  });

  it("mountISO calls client.bmc.mountISO with the iso_url", async () => {
    const { result } = renderHook(() => useBMC(PROFILE_ID));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    await act(() => result.current.mountISO("installer.iso"));
    expect(bmc.mountISO).toHaveBeenCalledWith("1", { iso_url: "installer.iso" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("a failed part is that part's error", async () => {
    bmc.getProvisionStatus.mockResolvedValue({
      success: false,
      error: { code: "HTTP_503", message: "baremetal provisioning not configured", status: 503 },
    });
    const { result } = renderHook(() => useBMC(PROFILE_ID));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.errors.provisionStatus).toBe("baremetal provisioning not configured");
    expect(result.current.provisionStatus).toBeNull();
    expect(result.current.power?.state).toBe("On");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("an older refresh that finishes last does not overwrite the state read after a mount", async () => {
    let mounted = false;
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let holdNext = false;
    bmc.mountISO.mockImplementation(async () => {
      mounted = true;
      return ok({ success: true });
    });
    bmc.getVirtualMediaStatus.mockImplementation(async () => {
      const snapshot = { mounted, image_url: mounted ? "installer.iso" : undefined };
      if (holdNext) {
        holdNext = false;
        await held;
      }
      return ok(snapshot);
    });

    const { result } = renderHook(() => useBMC(PROFILE_ID));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.virtualMedia?.mounted).toBe(false);

    holdNext = true;
    let stale!: Promise<void>;
    act(() => {
      stale = result.current.refetch();
    });

    await act(() => result.current.mountISO("installer.iso"));
    expect(result.current.virtualMedia?.mounted).toBe(true);

    release();
    await act(async () => {
      await stale;
    });
    expect(result.current.virtualMedia?.mounted).toBe(true);
    expect(result.current.virtualMedia?.image_url).toBe("installer.iso");
    expect(fetch).not.toHaveBeenCalled();
  });
});
