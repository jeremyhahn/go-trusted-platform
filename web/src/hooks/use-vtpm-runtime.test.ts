import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

// #2072: the runtime panel's running state comes from the server
// (IsVTPMRunning, GET /bundles/{id}/state) on mount, not only from the last
// start or stop reply in this tab.

type Deferred<T> = { promise: Promise<T>; resolve: (v: T) => void };
function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

function stateReply(running: boolean) {
  return { success: true, data: { bundle_id: "b1", running, socket_path: running ? "/run/b1.sock" : "" } };
}

const vtpm = {
  isBundleRunning: vi.fn(),
  startBundle: vi.fn(),
  stopBundle: vi.fn(),
  quoteBundle: vi.fn(),
  sealBundle: vi.fn(),
  unsealBundle: vi.fn(),
  extendBundlePCR: vi.fn(),
  readBundlePCR: vi.fn(),
};

vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  useVTPM: () => vtpm,
}));

import { ApiError, SERVICE_NOT_CONFIGURED, isServiceNotConfigured } from "trusted-platform-sdk";
import { useVTPMRuntime } from "./use-vtpm-runtime";

describe("useVTPMRuntime running state", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("reads the running state from the server on mount", async () => {
    vtpm.isBundleRunning.mockResolvedValue(stateReply(true));
    const { result } = renderHook(() => useVTPMRuntime("b1"));

    await waitFor(() => expect(result.current.runState).toBe("running"));
    expect(vtpm.isBundleRunning).toHaveBeenCalledWith("b1");
  });

  it("shows stopped when the server reports the bundle not running", async () => {
    vtpm.isBundleRunning.mockResolvedValue(stateReply(false));
    const { result } = renderHook(() => useVTPMRuntime("b1"));

    await waitFor(() => expect(result.current.runState).toBe("stopped"));
  });

  it("does not ask the server for an empty bundle id", async () => {
    const { result } = renderHook(() => useVTPMRuntime("  "));

    await act(async () => {});
    expect(vtpm.isBundleRunning).not.toHaveBeenCalled();
    expect(result.current.runState).toBe("unknown");
  });

  it("keeps unknown when the state read fails", async () => {
    vtpm.isBundleRunning.mockRejectedValue(new Error("boom"));
    const { result } = renderHook(() => useVTPMRuntime("b1"));

    await act(async () => {});
    expect(result.current.runState).toBe("unknown");
    expect(result.current.stateError).toBe("boom");
  });

  it("a late state read does not overwrite a newer start reply", async () => {
    const late = deferred<ReturnType<typeof stateReply>>();
    vtpm.isBundleRunning.mockReturnValue(late.promise);
    vtpm.startBundle.mockResolvedValue({
      success: true,
      data: { bundle_id: "b1", running: true, socket_path: "/run/b1.sock", status: { success: true } },
    });
    const { result } = renderHook(() => useVTPMRuntime("b1"));

    await act(async () => {
      await result.current.start.mutateAsync(undefined);
    });
    expect(result.current.runState).toBe("running");

    await act(async () => {
      late.resolve(stateReply(false));
      await late.promise;
    });
    expect(result.current.runState).toBe("running");
  });

  it("refreshState re-reads the server state", async () => {
    vtpm.isBundleRunning.mockResolvedValueOnce(stateReply(false)).mockResolvedValueOnce(stateReply(true));
    const { result } = renderHook(() => useVTPMRuntime("b1"));
    await waitFor(() => expect(result.current.runState).toBe("stopped"));

    await act(async () => {
      await result.current.refreshState();
    });
    expect(result.current.runState).toBe("running");
    expect(vtpm.isBundleRunning).toHaveBeenCalledTimes(2);
  });
});

// Capability gate: a node without the vTPM service answers the state read
// with the structured 503 SERVICE_NOT_CONFIGURED (or 501 when the route is
// not implemented); the hook then exposes a reason and sends no runtime call.
describe("useVTPMRuntime capability gate", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  async function expectEveryMutationRefused(result: { current: ReturnType<typeof useVTPMRuntime> }) {
    await act(async () => {
      await expect(result.current.start.mutateAsync(undefined)).rejects.toBeTruthy();
      await expect(result.current.stop.mutateAsync(undefined)).rejects.toBeTruthy();
      await expect(result.current.quote.mutateAsync({ nonce: "AA==", pcr_selection: [0] } as never)).rejects.toBeTruthy();
      await expect(result.current.seal.mutateAsync({ data: "AA==" } as never)).rejects.toBeTruthy();
      await expect(result.current.unseal.mutateAsync({ sealed_blob: "AA==" } as never)).rejects.toBeTruthy();
      await expect(result.current.readPCR.mutateAsync(0)).rejects.toBeTruthy();
      await expect(result.current.extendPCR.mutateAsync({ pcr_index: 16, digest: "AA==" } as never)).rejects.toBeTruthy();
    });
    expect(vtpm.startBundle).not.toHaveBeenCalled();
    expect(vtpm.stopBundle).not.toHaveBeenCalled();
    expect(vtpm.quoteBundle).not.toHaveBeenCalled();
    expect(vtpm.sealBundle).not.toHaveBeenCalled();
    expect(vtpm.unsealBundle).not.toHaveBeenCalled();
    expect(vtpm.readBundlePCR).not.toHaveBeenCalled();
    expect(vtpm.extendBundlePCR).not.toHaveBeenCalled();
  }

  it("gates every runtime control when the state read rejects with service-not-configured", async () => {
    const err = new ApiError("vTPM service not configured", "SERVICE_UNAVAILABLE", {
      status: 503,
      details: { reason: SERVICE_NOT_CONFIGURED },
    });
    expect(isServiceNotConfigured(err)).toBe(true);
    vtpm.isBundleRunning.mockRejectedValue(err);
    const { result } = renderHook(() => useVTPMRuntime("b1"));

    await waitFor(() => expect(result.current.gatedReason).not.toBeNull());
    expect(typeof result.current.gatedReason).toBe("string");
    await expectEveryMutationRefused(result);
  });

  it("gates every runtime control when the state reply is a not-configured error envelope", async () => {
    vtpm.isBundleRunning.mockResolvedValue({
      success: false,
      error: { message: "vTPM service not configured", status: 503, details: { reason: SERVICE_NOT_CONFIGURED } },
    });
    const { result } = renderHook(() => useVTPMRuntime("b1"));

    await waitFor(() => expect(result.current.gatedReason).not.toBeNull());
    await expectEveryMutationRefused(result);
  });

  it("gates every runtime control when the state read answers 501", async () => {
    vtpm.isBundleRunning.mockRejectedValue(new ApiError("not implemented", "NOT_IMPLEMENTED", { status: 501 }));
    const { result } = renderHook(() => useVTPMRuntime("b1"));

    await waitFor(() => expect(result.current.gatedReason).not.toBeNull());
    await expectEveryMutationRefused(result);
  });

  it("does not gate on an ordinary state read failure", async () => {
    vtpm.isBundleRunning.mockRejectedValue(new Error("boom"));
    const { result } = renderHook(() => useVTPMRuntime("b1"));

    await act(async () => {});
    expect(result.current.stateError).toBe("boom");
    expect(result.current.gatedReason).toBeNull();
  });
});
