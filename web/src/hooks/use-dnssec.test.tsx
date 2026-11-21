import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2060: useDNSSEC reads the zone's DNSSEC status through client.dns
// (the SDK service is the network boundary, mocked here) and signs the zone.

const { dns } = vi.hoisted(() => ({
  dns: { getDNSSECStatus: vi.fn(), signZone: vi.fn() },
}));

vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  useDNS: () => dns,
}));

import { useDNSSEC } from "./use-dnssec";

const unsigned = { enabled: true, zoneSigned: false, keys: [], dsRecords: [], algorithm: "", keySize: "" };
const signed = {
  enabled: true,
  zoneSigned: true,
  keys: [{}],
  dsRecords: [{ keyTag: 12345, algorithm: 13, digestType: 2, digest: "ABCDEF" }],
  algorithm: "ECDSAP256SHA256",
  keySize: "256",
};

beforeEach(() => {
  dns.getDNSSECStatus.mockReset();
  dns.signZone.mockReset();
});

afterEach(() => {
  cleanup();
});

describe("useDNSSEC", () => {
  it("reads the zone's DNSSEC status", async () => {
    dns.getDNSSECStatus.mockResolvedValue({ data: { status: unsigned }, success: true });
    const { result } = renderHook(() => useDNSSEC("example.com."));

    await waitFor(() => expect(result.current.status).toEqual(unsigned));
    expect(dns.getDNSSECStatus).toHaveBeenCalledTimes(1);
    expect(dns.getDNSSECStatus).toHaveBeenCalledWith("example.com.");
  });

  it("signs the zone and refetches the status", async () => {
    dns.getDNSSECStatus
      .mockResolvedValueOnce({ data: { status: unsigned }, success: true })
      .mockResolvedValueOnce({ data: { status: signed }, success: true });
    dns.signZone.mockResolvedValue({
      data: { status: { success: true, message: "zone signed successfully" } },
      success: true,
    });
    const { result } = renderHook(() => useDNSSEC("example.com."));
    await waitFor(() => expect(result.current.status).toEqual(unsigned));

    await act(() => result.current.signZone());

    expect(dns.signZone).toHaveBeenCalledTimes(1);
    expect(dns.signZone).toHaveBeenCalledWith("example.com.");
    expect(dns.getDNSSECStatus).toHaveBeenCalledTimes(2);
    await waitFor(() => expect(result.current.status?.zoneSigned).toBe(true));
  });

  it("rejects when the server refuses the signing and does not refetch", async () => {
    dns.getDNSSECStatus.mockResolvedValue({ data: { status: unsigned }, success: true });
    dns.signZone.mockResolvedValue({ success: false, error: { code: "NOT_FOUND", message: "zone not found" } });
    const { result } = renderHook(() => useDNSSEC("example.com."));
    await waitFor(() => expect(result.current.status).toEqual(unsigned));

    await act(async () => {
      await expect(result.current.signZone()).rejects.toMatchObject({ message: "zone not found" });
    });
    expect(dns.getDNSSECStatus).toHaveBeenCalledTimes(1);
  });

  it("does not fetch without a zone", async () => {
    const { result } = renderHook(() => useDNSSEC(""));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(dns.getDNSSECStatus).not.toHaveBeenCalled();
  });
});
