import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useBMC } from "./use-bmc";

/**
 * useBMC reads the BMC REST routes in the server's JSON shapes
 * (pkg/webservice/v1/bmc/types.go, pkg/bmc/types.go) and mounts an ISO
 * with the iso_url the handler requires (#1736).
 */

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
    profile_id: "r640-01",
    status: "installing",
    started_at: "2026-11-12T00:00:00Z",
    updated_at: "2026-11-12T00:05:00Z",
  },
  cert: {
    subject: "CN=idrac-r640-01",
    issuer: "CN=Platform CA",
    serial_number: "01",
    not_before: "2026-11-12T00:00:00Z",
    not_after: "2027-11-12T00:00:00Z",
    days_remaining: 365,
    fingerprint: "AA:BB:CC",
  },
};

type FetchCall = { url: string; init?: RequestInit };

describe("useBMC", () => {
  let calls: FetchCall[];

  beforeEach(() => {
    calls = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        calls.push({ url, init });
        const op = url.split("/").pop() ?? "";
        const payload = init?.method && init.method !== "GET" ? { success: true } : PAYLOADS[op];
        return new Response(JSON.stringify({ success: true, payload }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      })
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("reads every part in the server's shapes", async () => {
    const { result } = renderHook(() => useBMC("r640-01"));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.errors).toEqual({});
    expect(result.current.sensors?.[0].value).toBe(42);
    expect(result.current.virtualMedia?.mounted).toBe(true);
    expect(result.current.virtualMedia?.image_url).toBe("rescue.iso");
    expect(result.current.systemInfo?.product).toBe("PowerEdge R640");
    expect(result.current.provisionStatus?.status).toBe("installing");
    expect(result.current.certificate?.fingerprint).toBe("AA:BB:CC");
  });

  it("mountISO POSTs the iso_url", async () => {
    const { result } = renderHook(() => useBMC("r640-01"));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    await act(() => result.current.mountISO("installer.iso"));
    const post = calls.find((c) => c.init?.method === "POST");
    expect(post?.url).toBe("/api/v1/bmc/r640-01/virtual-media");
    expect(post?.init?.body).toBe('{"iso_url":"installer.iso"}');
  });
});
