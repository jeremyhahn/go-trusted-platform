import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { PXEDeviceInfo } from "trusted-platform-sdk";

// #2062: the PXE device actions reach the webservice through client.pxe
// (network boundary, mocked here); the hook toasts and refreshes only on
// success.

const { pxe, toast } = vi.hoisted(() => ({
  pxe: {
    authorizeDevice: vi.fn(),
    quarantineDevice: vi.fn(),
    retryDevice: vi.fn(),
    removeDevice: vi.fn(),
  },
  toast: vi.fn(),
}));

vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  usePXE: () => pxe,
}));

vi.mock("@/hooks/use-toast", () => ({ useToast: () => ({ toast }) }));
vi.mock("./use-toast", () => ({ useToast: () => ({ toast }) }));

import { usePXEDeviceActions } from "./use-pxe-device-actions";

const device = { id: "dev-1", macAddress: "00:11:22:33:44:55", state: "FAILED" } as PXEDeviceInfo;

beforeEach(() => {
  vi.clearAllMocks();
  pxe.authorizeDevice.mockResolvedValue({ data: {} });
  pxe.quarantineDevice.mockResolvedValue({ data: {} });
  pxe.retryDevice.mockResolvedValue({ data: {} });
  pxe.removeDevice.mockResolvedValue({ data: {} });
});

describe("usePXEDeviceActions", () => {
  it("authorizes with the target VLAN, toasts and refreshes", async () => {
    const onChanged = vi.fn();
    const { result } = renderHook(() => usePXEDeviceActions(onChanged));
    let ok = false;
    await act(async () => {
      ok = await result.current.authorize(device, 100);
    });
    expect(ok).toBe(true);
    expect(pxe.authorizeDevice).toHaveBeenCalledWith({ deviceId: "dev-1", targetVlan: 100 });
    expect(onChanged).toHaveBeenCalledTimes(1);
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Device authorized", description: "00:11:22:33:44:55", variant: "success" }),
    );
  });

  it("quarantines with the reason", async () => {
    const onChanged = vi.fn();
    const { result } = renderHook(() => usePXEDeviceActions(onChanged));
    await act(async () => {
      expect(await result.current.quarantine(device, "tamper")).toBe(true);
    });
    expect(pxe.quarantineDevice).toHaveBeenCalledWith({ deviceId: "dev-1", reason: "tamper" });
    expect(onChanged).toHaveBeenCalledTimes(1);
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Device quarantined" }));
  });

  it("retries by device id", async () => {
    const { result } = renderHook(() => usePXEDeviceActions());
    await act(async () => {
      expect(await result.current.retry(device)).toBe(true);
    });
    expect(pxe.retryDevice).toHaveBeenCalledWith("dev-1");
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Device retry started" }));
  });

  it("removes by device id", async () => {
    const onChanged = vi.fn();
    const { result } = renderHook(() => usePXEDeviceActions(onChanged));
    await act(async () => {
      expect(await result.current.remove(device)).toBe(true);
    });
    expect(pxe.removeDevice).toHaveBeenCalledWith("dev-1");
    expect(onChanged).toHaveBeenCalledTimes(1);
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Device removed" }));
  });

  it("returns false, toasts the error and does not refresh when the call throws", async () => {
    pxe.removeDevice.mockRejectedValue(new Error("boom"));
    const onChanged = vi.fn();
    const { result } = renderHook(() => usePXEDeviceActions(onChanged));
    let ok = true;
    await act(async () => {
      ok = await result.current.remove(device);
    });
    expect(ok).toBe(false);
    expect(onChanged).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledWith({
      title: "Failed to remove device",
      description: "boom",
      variant: "destructive",
    });
  });

  it("marks the device pending while a call is in flight and clears it after", async () => {
    let resolve: (v: unknown) => void = () => {};
    pxe.retryDevice.mockReturnValue(new Promise((r) => (resolve = r)));
    const { result } = renderHook(() => usePXEDeviceActions());
    let call: Promise<boolean> = Promise.resolve(false);
    act(() => {
      call = result.current.retry(device);
    });
    await waitFor(() => expect(result.current.isPending("dev-1")).toBe(true));
    await act(async () => {
      resolve({ data: {} });
      await call;
    });
    await waitFor(() => expect(result.current.isPending("dev-1")).toBe(false));
  });

  // #2166 Codex: a completion on one device must not re-enable another
  // device's controls while its own request is still running.
  it("keeps each device pending until its own request finishes", async () => {
    const deviceB = { id: "dev-2", macAddress: "00:11:22:33:44:66", state: "FAILED" } as PXEDeviceInfo;
    const a = deferred();
    const b = deferred();
    pxe.retryDevice.mockReturnValueOnce(a.promise).mockReturnValueOnce(b.promise);
    const { result } = renderHook(() => usePXEDeviceActions());
    let callA: Promise<boolean> = Promise.resolve(false);
    let callB: Promise<boolean> = Promise.resolve(false);
    act(() => {
      callA = result.current.retry(device);
      callB = result.current.retry(deviceB);
    });
    expect(result.current.isPending("dev-1")).toBe(true);
    expect(result.current.isPending("dev-2")).toBe(true);
    await act(async () => {
      b.resolve({ data: {} });
      await callB;
    });
    expect(result.current.isPending("dev-2")).toBe(false);
    expect(result.current.isPending("dev-1")).toBe(true);
    await act(async () => {
      a.resolve({ data: {} });
      await callA;
    });
    expect(result.current.isPending("dev-1")).toBe(false);
  });

  it("the same device stays pending while a second action on it is outstanding", async () => {
    const first = deferred();
    const second = deferred();
    pxe.retryDevice.mockReturnValueOnce(first.promise);
    pxe.removeDevice.mockReturnValueOnce(second.promise);
    const { result } = renderHook(() => usePXEDeviceActions());
    let callRetry: Promise<boolean> = Promise.resolve(false);
    let callRemove: Promise<boolean> = Promise.resolve(false);
    act(() => {
      callRetry = result.current.retry(device);
      callRemove = result.current.remove(device);
    });
    expect(result.current.isPending("dev-1")).toBe(true);
    await act(async () => {
      first.resolve({ data: {} });
      await callRetry;
    });
    expect(result.current.isPending("dev-1")).toBe(true);
    await act(async () => {
      second.resolve({ data: {} });
      await callRemove;
    });
    expect(result.current.isPending("dev-1")).toBe(false);
  });
});

function deferred(): { promise: Promise<unknown>; resolve: (v: unknown) => void } {
  let resolve: (v: unknown) => void = () => {};
  const promise = new Promise((r) => (resolve = r));
  return { promise, resolve };
}
