import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";

const ok = <T,>(data: T) => Promise.resolve({ success: true, data });

const platform = {
  getStatus: vi.fn(),
  getVersion: vi.fn(),
  getConfig: vi.fn(),
  listServices: vi.fn(),
  reloadConfig: vi.fn(),
  startService: vi.fn(),
  stopService: vi.fn(),
  restartService: vi.fn(),
  getServiceStatus: vi.fn(),
  liveness: vi.fn(),
  readiness: vi.fn(),
  updateConfig: vi.fn(),
  listEntityTypes: vi.fn(),
  shutdown: vi.fn(),
};

vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  usePlatform: () => platform,
}));

import { usePlatformDaemon } from "./use-platform-daemon";

describe("usePlatformDaemon (#2047)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    platform.getStatus.mockImplementation(() => ok({ status: "running" }));
    platform.getVersion.mockImplementation(() => ok({ version: "1.2.3" }));
    platform.getConfig.mockImplementation(() => ok({ server: { port: 8443 } }));
    platform.listServices.mockImplementation(() => ok({ services: [] }));
    platform.liveness.mockImplementation(() => ok({ alive: true, status: "healthy" }));
    platform.readiness.mockImplementation(() => ok({ ready: false, status: "unhealthy" }));
    platform.listEntityTypes.mockImplementation(() =>
      ok({ entity_types: [{ name: "tenant", count: 2, status: "active" }], total_entities: 2 })
    );
  });

  it("reads the liveness and readiness probes", async () => {
    const { result } = renderHook(() => usePlatformDaemon());
    await waitFor(() => expect(result.current.liveness.data?.alive).toBe(true));
    await waitFor(() => expect(result.current.readiness.data?.ready).toBe(false));
    expect(platform.liveness).toHaveBeenCalledTimes(1);
    expect(platform.readiness).toHaveBeenCalledTimes(1);
  });

  it("lists the entity types", async () => {
    const { result } = renderHook(() => usePlatformDaemon());
    await waitFor(() =>
      expect(result.current.entityTypes.data?.entity_types?.[0]?.name).toBe("tenant")
    );
  });

  it("updateConfig sends the section and re-reads the configuration", async () => {
    platform.updateConfig.mockImplementation(() => ok({ applied: true, message: "applied" }));
    const { result } = renderHook(() => usePlatformDaemon());
    await waitFor(() => expect(platform.getConfig).toHaveBeenCalledTimes(1));

    await act(async () => {
      await result.current.updateConfig("logging", { level: "debug" }, true);
    });
    expect(platform.updateConfig).toHaveBeenCalledWith({
      section: "logging",
      values: { level: "debug" },
      persist: true,
    });
    await waitFor(() => expect(platform.getConfig).toHaveBeenCalledTimes(2));
  });

  it("updateConfig throws the server's refusal", async () => {
    platform.updateConfig.mockImplementation(() =>
      Promise.resolve({ success: false, error: { status: 400, message: "unknown section" } })
    );
    const { result } = renderHook(() => usePlatformDaemon());
    await expect(result.current.updateConfig("nope", {}, false)).rejects.toThrow("unknown section");
  });

  it("shutdown sends graceful and the timeout, pending while in flight", async () => {
    let resolve!: (v: unknown) => void;
    platform.shutdown.mockImplementation(() => new Promise((r) => (resolve = r)));
    const { result } = renderHook(() => usePlatformDaemon());

    let done!: Promise<unknown>;
    act(() => {
      done = result.current.shutdown({ graceful: true, timeoutSeconds: 30 });
    });
    expect(platform.shutdown).toHaveBeenCalledWith({ graceful: true, timeout_seconds: 30 });
    await waitFor(() => expect(result.current.isPending("shutdown")).toBe(true));
    await act(async () => {
      resolve({ success: true, data: { success: true, message: "shutdown completed successfully" } });
      await done;
    });
    expect(result.current.isPending("shutdown")).toBe(false);
  });
});
