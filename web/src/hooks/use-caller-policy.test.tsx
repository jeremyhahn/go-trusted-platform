import { renderHook, waitFor, act } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useCallerPolicy } from "./use-caller-policy";

// #2038: DescribeCallerPolicy (GET /v1/attestation/callers) in the console.

const service = { describeCallers: vi.fn() };

vi.mock("trusted-platform-sdk", () => ({
  useAttestation: () => service,
}));

const policy = {
  strategy: "allowlist",
  identities: ["spiffe://a"],
  list_valid: true,
  anchors_configured: true,
  attested_peers_available: false,
  admits_nobody: false,
};

describe("useCallerPolicy", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("loads the caller policy on mount", async () => {
    service.describeCallers.mockResolvedValue({ success: true, data: policy });
    const { result } = renderHook(() => useCallerPolicy());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(service.describeCallers).toHaveBeenCalledTimes(1);
    expect(result.current.policy).toEqual(policy);
    expect(result.current.error).toBeUndefined();
  });

  it("keeps the server's error and reloads on demand", async () => {
    service.describeCallers.mockResolvedValueOnce({
      success: false,
      error: { status: 503, message: "caller gate not configured" },
    });
    const { result } = renderHook(() => useCallerPolicy());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBe("caller gate not configured");
    expect(result.current.policy).toBeUndefined();

    service.describeCallers.mockResolvedValueOnce({ success: true, data: policy });
    await act(async () => {
      await result.current.reload();
    });
    expect(result.current.policy).toEqual(policy);
    expect(result.current.error).toBeUndefined();
  });
});
