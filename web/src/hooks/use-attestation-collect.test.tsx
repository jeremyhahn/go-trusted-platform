import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useAttestationCollect } from "./use-attestation-collect";

// #1747 Codex round 2 (P1): the service answers every VM and container
// collect with ErrTPMSessionNotConfigured. The hook names that state as
// "not available" instead of passing a raw internal error through.

const service = {
  collectHostAttestation: vi.fn(),
  collectVMAttestation: vi.fn(),
  collectContainerAttestation: vi.fn(),
  deleteManifest: vi.fn(),
};

vi.mock("trusted-platform-sdk", () => ({
  useAttestation: () => service,
}));

function tpmSessionFailure(op: string) {
  return {
    success: false,
    error: {
      status: 500,
      message: `attestation/service: ${op} requires a daemon-managed TPM session which is not configured`,
    },
  };
}

describe("useAttestationCollect workload collection", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("reports VM collection as unavailable on the service's TPM-session failure", async () => {
    service.collectVMAttestation.mockResolvedValue(tpmSessionFailure("CollectVMAttestation"));
    const { result } = renderHook(() => useAttestationCollect());

    let ok = true;
    await act(async () => {
      ok = await result.current.collectVM("vm-7");
    });

    expect(ok).toBe(false);
    expect(result.current.operation).toBe("collectVM");
    expect(result.current.unavailable).toBe(true);
    expect(result.current.error).toContain("not available");
  });

  it("reports container collection as unavailable on the service's TPM-session failure", async () => {
    service.collectContainerAttestation.mockResolvedValue(
      tpmSessionFailure("CollectContainerAttestation")
    );
    const { result } = renderHook(() => useAttestationCollect());

    let ok = true;
    await act(async () => {
      ok = await result.current.collectContainer("ctr-9");
    });

    expect(ok).toBe(false);
    expect(result.current.operation).toBe("collectContainer");
    expect(result.current.unavailable).toBe(true);
    expect(result.current.error).toContain("not available");
  });

  it("passes any other failure through unchanged", async () => {
    service.collectVMAttestation.mockResolvedValue({
      success: false,
      error: { status: 404, message: "vm not found" },
    });
    const { result } = renderHook(() => useAttestationCollect());

    await act(async () => {
      await result.current.collectVM("vm-x");
    });

    expect(result.current.unavailable).toBeFalsy();
    expect(result.current.error).toBe("vm not found");
  });
});
