import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useBMC } from "./use-bmc";

/**
 * useBMC reads the BMC REST routes in the server's JSON shapes
 * (pkg/webservice/v1/bmc/types.go, pkg/bmc/types.go) through the SDK's
 * BMCService and mounts an ISO with the iso_url the handler requires (#1736).
 */

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

/** One BMC call as the SDK service saw it: the route op, the method and the body */
interface Call {
  profile: string;
  op: string;
  method: "GET" | "POST" | "DELETE";
  body?: unknown;
}

type Envelope = { success: boolean; data?: unknown; error?: { code: string; message: string } };
type Handler = (call: Call) => Promise<Envelope>;

const sdk = vi.hoisted(() => ({ handler: undefined as unknown as Handler }));

/** Every BMCService method routes to sdk.handler with its route op */
vi.mock("trusted-platform-sdk", () => {
  const send = (profile: string, op: string, method: Call["method"], body?: unknown) =>
    sdk.handler({ profile, op, method, body });
  const bmc = {
    getPowerStatus: (id: string) => send(id, "power", "GET"),
    powerAction: (id: string, action: string) => send(id, "power", "POST", { action }),
    getBootDevice: (id: string) => send(id, "boot-device", "GET"),
    setBootDevice: (id: string, request: unknown) => send(id, "boot-device", "POST", request),
    getVirtualMediaStatus: (id: string) => send(id, "virtual-media", "GET"),
    mountISO: (id: string, request: unknown) => send(id, "virtual-media", "POST", request),
    unmountISO: (id: string) => send(id, "virtual-media", "DELETE"),
    getSensors: (id: string) => send(id, "sensors", "GET"),
    getSystemInfo: (id: string) => send(id, "system-info", "GET"),
    provision: (id: string) => send(id, "provision", "POST", {}),
    getProvisionStatus: (id: string) => send(id, "provision", "GET"),
    getWebCertificate: (id: string) => send(id, "cert", "GET"),
  };
  return { usePlatformClient: () => ({ bmc }) };
});

const ok = (data: unknown): Envelope => ({ success: true, data });
const fail = (message: string): Envelope => ({ success: false, error: { code: "BMC_ERROR", message } });

describe("useBMC", () => {
  let calls: Call[];

  beforeEach(() => {
    calls = [];
    sdk.handler = async (call) => {
      calls.push(call);
      return ok(call.method !== "GET" ? { success: true } : PAYLOADS[call.op]);
    };
  });

  afterEach(() => {
    cleanup();
  });

  it("reads every part in the server's shapes", async () => {
    const { result } = renderHook(() => useBMC(PROFILE_ID));
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
    const { result } = renderHook(() => useBMC(PROFILE_ID));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    await act(() => result.current.mountISO("installer.iso"));
    const post = calls.find((c) => c.method === "POST");
    expect(post?.profile).toBe(PROFILE_ID);
    expect(post?.op).toBe("virtual-media");
    expect(post?.body).toEqual({ iso_url: "installer.iso" });
  });

  it.each(["on", "off", "reset", "cycle"] as const)(
    "powerAction(%s) POSTs the action to /power and refreshes the power state",
    async (action) => {
      const { result } = renderHook(() => useBMC(PROFILE_ID));
      await waitFor(() => expect(result.current.isLoading).toBe(false));
      const readsBefore = calls.filter((c) => c.op === "power" && c.method === "GET").length;
      await act(() => result.current.powerAction(action));
      const post = calls.find((c) => c.method === "POST");
      expect(post?.op).toBe("power");
      expect(post?.body).toEqual({ action });
      const readsAfter = calls.filter((c) => c.op === "power" && c.method === "GET").length;
      expect(readsAfter).toBeGreaterThan(readsBefore);
    }
  );

  it("powerAction surfaces the server's refusal", async () => {
    const { result } = renderHook(() => useBMC(PROFILE_ID));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    sdk.handler = async (call) => {
      calls.push(call);
      return call.method === "POST" ? fail("bmc unreachable") : ok(PAYLOADS[call.op]);
    };
    await expect(act(() => result.current.powerAction("off"))).rejects.toThrow("bmc unreachable");
  });

  it("an older refresh that finishes last does not overwrite the state read after a mount", async () => {
    let mounted = false;
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let holdNext = false;
    sdk.handler = async ({ op, method }) => {
      if (method !== "GET") {
        if (op === "virtual-media" && method === "POST") {
          mounted = true;
        }
        return ok({ success: true });
      }
      if (op === "virtual-media") {
        const snapshot = { mounted, image_url: mounted ? "installer.iso" : undefined };
        if (holdNext) {
          holdNext = false;
          await held;
        }
        return ok(snapshot);
      }
      return ok(PAYLOADS[op]);
    };

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
  });

  it("a failed mutation that invalidates the initial read still settles loading", async () => {
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let holdFirst = true;
    sdk.handler = async ({ op, method }) => {
      if (method !== "GET") {
        return fail("BMC unreachable");
      }
      if (op === "power" && holdFirst) {
        holdFirst = false;
        await held;
      }
      return ok(PAYLOADS[op]);
    };

    const { result } = renderHook(() => useBMC(PROFILE_ID));
    expect(result.current.isLoading).toBe(true);

    let failure: unknown;
    await act(async () => {
      try {
        await result.current.mountISO("installer.iso");
      } catch (err) {
        failure = err;
      }
    });
    expect((failure as Error | undefined)?.message).toBe("BMC unreachable");

    release();
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.systemInfo?.product).toBe("PowerEdge R640");
  });

  it("a mutation for an earlier profile does not refresh it over the current profile", async () => {
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    const reads: string[] = [];
    sdk.handler = async ({ profile, op, method }) => {
      if (method !== "GET") {
        await held;
        return ok({ success: true });
      }
      reads.push(`${profile}/${op}`);
      return ok(
        op === "system-info" ? { ...(PAYLOADS[op] as object), product: `profile-${profile}` } : PAYLOADS[op]
      );
    };

    const { result, rerender } = renderHook(({ id }) => useBMC(id), {
      initialProps: { id: "1" },
    });
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    let pending!: Promise<void>;
    act(() => {
      pending = result.current.mountISO("installer.iso");
    });

    rerender({ id: "2" });
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.systemInfo?.product).toBe("profile-2");

    reads.length = 0;
    release();
    await act(async () => {
      await pending;
    });

    expect(reads.filter((r) => r.startsWith("1/"))).toEqual([]);
    expect(result.current.isLoading).toBe(false);
    expect(result.current.systemInfo?.product).toBe("profile-2");
  });
});
