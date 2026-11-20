import { renderHook, waitFor, act } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useDeviceVerdicts } from "./use-device-verdicts";

// #2038: PollDeviceVerdicts (GET /v1/attestation/verdicts) in the console.

const service = { pollDeviceVerdicts: vi.fn() };

vi.mock("trusted-platform-sdk", () => ({
  useAttestation: () => service,
}));

function verdict(eventId: string, passed: boolean) {
  return {
    eventId,
    recordedAt: "2026-11-20T00:00:00Z",
    deviceId: "7",
    tenantId: "t-1",
    hostId: "h-1",
    serial: `SN-${eventId}`,
    passed,
    cryptographic: false,
    reason: passed ? "" : "pcr mismatch",
  };
}

describe("useDeviceVerdicts", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("polls once on mount without waiting", async () => {
    service.pollDeviceVerdicts.mockResolvedValue({
      success: true,
      data: { cursor: "c1", verdicts: [verdict("e1", true)] },
    });
    const { result } = renderHook(() => useDeviceVerdicts());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(service.pollDeviceVerdicts).toHaveBeenCalledWith({});
    expect(result.current.verdicts.map((v) => v.eventId)).toEqual(["e1"]);
    expect(result.current.cursor).toBe("c1");
  });

  it("continues from the cursor and appends the next page", async () => {
    service.pollDeviceVerdicts
      .mockResolvedValueOnce({ success: true, data: { cursor: "c1", verdicts: [verdict("e1", true)] } })
      .mockResolvedValueOnce({ success: true, data: { cursor: "c2", verdicts: [verdict("e2", false)] } });
    const { result } = renderHook(() => useDeviceVerdicts());
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.poll();
    });

    expect(service.pollDeviceVerdicts).toHaveBeenLastCalledWith({ cursor: "c1" });
    expect(result.current.verdicts.map((v) => v.eventId)).toEqual(["e1", "e2"]);
    expect(result.current.cursor).toBe("c2");
  });

  it("keeps the verdicts it has when a poll fails", async () => {
    service.pollDeviceVerdicts
      .mockResolvedValueOnce({ success: true, data: { cursor: "c1", verdicts: [verdict("e1", true)] } })
      .mockResolvedValueOnce({ success: false, error: { status: 403, message: "no tenant in session" } });
    const { result } = renderHook(() => useDeviceVerdicts());
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      await result.current.poll();
    });

    expect(result.current.error).toBe("no tenant in session");
    expect(result.current.verdicts).toHaveLength(1);
    expect(result.current.cursor).toBe("c1");
  });
});
