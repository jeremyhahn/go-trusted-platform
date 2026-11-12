import { renderHook } from "@testing-library/react";
import type { DeviceLifecycleResponse } from "trusted-platform-sdk";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useDeviceToggle, type DeviceToggleRequest } from "./use-device-toggle";

type MutationFn = (req: DeviceToggleRequest) => Promise<DeviceLifecycleResponse>;
interface MutationOptions {
  onSuccess: (result: DeviceLifecycleResponse, req: DeviceToggleRequest) => void;
  onError: (error: Error, req: DeviceToggleRequest) => void;
}

const sdk = vi.hoisted(() => ({
  enableDevice: vi.fn(),
  disableDevice: vi.fn(),
  captured: { fn: undefined as unknown, options: undefined as unknown },
  mutationResult: { mutate: () => undefined },
}));
const toastSpy = vi.hoisted(() => vi.fn());

vi.mock("trusted-platform-sdk", () => ({
  useDevice: () => ({ enableDevice: sdk.enableDevice, disableDevice: sdk.disableDevice }),
  useMutation: (fn: unknown, options: unknown) => {
    sdk.captured.fn = fn;
    sdk.captured.options = options;
    return sdk.mutationResult;
  },
}));

vi.mock("./use-toast", () => ({
  useToast: () => ({ toast: toastSpy, dismiss: vi.fn(), toasts: [] }),
}));

function setup(onChanged?: () => void) {
  const { result } = renderHook(() => useDeviceToggle(onChanged));
  return {
    result: result.current,
    fn: sdk.captured.fn as MutationFn,
    options: sdk.captured.options as MutationOptions,
  };
}

const response = (extra: Partial<DeviceLifecycleResponse> = {}) =>
  ({ ...extra }) as DeviceLifecycleResponse;

describe("useDeviceToggle", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sdk.captured.fn = undefined;
    sdk.captured.options = undefined;
  });

  it("returns the mutation result of useMutation", () => {
    expect(setup().result).toBe(sdk.mutationResult);
  });

  it("sends enable to enableDevice with the device id", async () => {
    const reply = response();
    sdk.enableDevice.mockResolvedValue(reply);
    const { fn } = setup();
    await expect(fn({ id: "dev-1", toggle: "enable" })).resolves.toBe(reply);
    expect(sdk.enableDevice).toHaveBeenCalledWith("dev-1");
    expect(sdk.disableDevice).not.toHaveBeenCalled();
  });

  it("sends disable to disableDevice with the device id", async () => {
    const reply = response();
    sdk.disableDevice.mockResolvedValue(reply);
    const { fn } = setup();
    await expect(fn({ id: "dev-2", toggle: "disable" })).resolves.toBe(reply);
    expect(sdk.disableDevice).toHaveBeenCalledWith("dev-2");
    expect(sdk.enableDevice).not.toHaveBeenCalled();
  });

  it("passes an empty id through unchanged", async () => {
    sdk.disableDevice.mockResolvedValue(response());
    const { fn } = setup();
    await fn({ id: "", toggle: "disable" });
    expect(sdk.disableDevice).toHaveBeenCalledWith("");
  });

  it("propagates a service rejection", async () => {
    sdk.enableDevice.mockRejectedValue(new Error("boom"));
    const { fn } = setup();
    await expect(fn({ id: "dev-3", toggle: "enable" })).rejects.toThrow("boom");
  });

  it("toasts an applied enable and calls onChanged", () => {
    const onChanged = vi.fn();
    const { options } = setup(onChanged);
    options.onSuccess(response(), { id: "dev-1", toggle: "enable" });
    expect(toastSpy).toHaveBeenCalledWith({
      title: "Device enabled",
      description: "Device re-admitted to quarantine; it is restored once it passes attestation.",
    });
    expect(onChanged).toHaveBeenCalledTimes(1);
  });

  it("words an enable that requested re-attestation", () => {
    const { options } = setup();
    options.onSuccess(response({ reattestation_requested: true } as Partial<DeviceLifecycleResponse>), {
      id: "dev-1",
      toggle: "enable",
    });
    expect(toastSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Device enabled",
        description: expect.stringContaining("re-attestation was requested"),
      })
    );
  });

  it("toasts an applied disable", () => {
    const onChanged = vi.fn();
    const { options } = setup(onChanged);
    options.onSuccess(response(), { id: "dev-1", toggle: "disable" });
    expect(toastSpy).toHaveBeenCalledWith({
      title: "Device disabled",
      description: "Device disabled: its switch port is blocked.",
    });
    expect(onChanged).toHaveBeenCalledTimes(1);
  });

  it("succeeds without an onChanged callback", () => {
    const { options } = setup();
    expect(() => options.onSuccess(response(), { id: "dev-1", toggle: "enable" })).not.toThrow();
    expect(toastSpy).toHaveBeenCalledTimes(1);
  });

  it("toasts a refused enable as destructive with the server reason and skips onChanged", () => {
    const onChanged = vi.fn();
    const { options } = setup(onChanged);
    options.onError(new Error("device is decommissioned"), { id: "dev-1", toggle: "enable" });
    expect(toastSpy).toHaveBeenCalledWith({
      title: "Enable refused",
      description: "device is decommissioned",
      variant: "destructive",
    });
    expect(onChanged).not.toHaveBeenCalled();
  });

  it("toasts a refused disable as destructive", () => {
    const { options } = setup();
    options.onError(new Error(""), { id: "dev-1", toggle: "disable" });
    expect(toastSpy).toHaveBeenCalledWith({
      title: "Disable refused",
      description: "",
      variant: "destructive",
    });
  });
});
