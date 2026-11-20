import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ceremony = {
  getStatus: vi.fn(),
  init: vi.fn(),
  claimCertBegin: vi.fn(),
  claimCertComplete: vi.fn(),
  claimShareBegin: vi.fn(),
  claimShareComplete: vi.fn(),
  signCSR: vi.fn(),
};

vi.mock("trusted-platform-sdk", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return { ...actual, usePlatformClient: () => ({ ceremony }) };
});

import { useCeremony } from "./use-ceremony";

const ok = <T,>(data: T) => ({ data, status: 200, headers: {} });

const STATUS = {
  ceremony_id: "cer-1",
  state: "initialized",
  threshold: "2-of-3",
  officers_enrolled: 1,
  officers_required: 3,
};

describe("useCeremony", () => {
  beforeEach(() => {
    for (const fn of Object.values(ceremony)) fn.mockReset();
    ceremony.getStatus.mockResolvedValue(ok(STATUS));
  });
  afterEach(() => cleanup());

  it("reads the status on mount", async () => {
    const { result } = renderHook(() => useCeremony());
    await waitFor(() => expect(result.current.status).toEqual(STATUS));
    expect(ceremony.getStatus).toHaveBeenCalledTimes(1);
    expect(result.current.statusError).toBeNull();
  });

  it("keeps the status error when the server refuses (no ceremony backend)", async () => {
    ceremony.getStatus.mockRejectedValue(new Error("ceremony not configured"));
    const { result } = renderHook(() => useCeremony());
    await waitFor(() => expect(result.current.statusError).toBe("ceremony not configured"));
    expect(result.current.status).toBeNull();
  });

  it("init posts the wire body and reads the status again", async () => {
    ceremony.init.mockResolvedValue(ok({ ceremony_id: "cer-1", state: "initialized", admin_cert_pem: "C", admin_key_pem: "K", spki_pin: "P" }));
    const { result } = renderHook(() => useCeremony());
    await waitFor(() => expect(result.current.status).not.toBeNull());
    let out: unknown;
    await act(async () => {
      out = await result.current.init({ so_pin: "1", user_pin: "2", threshold: "2-of-3", hostname: "h", sans: ["a", "b"] });
    });
    expect(ceremony.init).toHaveBeenCalledWith({ so_pin: "1", user_pin: "2", threshold: "2-of-3", hostname: "h", sans: ["a", "b"] });
    expect(out).toMatchObject({ ceremony_id: "cer-1", spki_pin: "P" });
    expect(ceremony.getStatus).toHaveBeenCalledTimes(2);
  });

  it("each step calls its SDK method with the wire body and returns the data", async () => {
    ceremony.claimCertBegin.mockResolvedValue(ok({ nonce: "n1", challenge_id: "c1" }));
    ceremony.claimCertComplete.mockResolvedValue(ok({ certificate_pem: "CERT", chain_pem: "CHAIN" }));
    ceremony.claimShareBegin.mockResolvedValue(ok({ nonce: "n2" }));
    ceremony.claimShareComplete.mockResolvedValue(ok({ share: "SHARE", index: 2 }));
    ceremony.signCSR.mockResolvedValue(ok({ certificate_pem: "C2", chain_pem: "CH2" }));
    const { result } = renderHook(() => useCeremony());
    await waitFor(() => expect(result.current.status).not.toBeNull());

    await act(async () => {
      expect(await result.current.claimCertBegin({ username: "o1", authenticator_type: "piv", slot: "9a" })).toEqual({ nonce: "n1", challenge_id: "c1" });
      expect(await result.current.claimCertComplete({ username: "o1", nonce: "n1", signature: "sig" })).toEqual({ certificate_pem: "CERT", chain_pem: "CHAIN" });
      expect(await result.current.claimShareBegin({ username: "o1" })).toEqual({ nonce: "n2" });
      expect(await result.current.claimShareComplete({ username: "o1", nonce: "n2", signature: "c2ln" })).toEqual({ share: "SHARE", index: 2 });
      expect(await result.current.signCSR({ username: "o1", so_pin: "1", csr_pem: "CSR", role: "admin" })).toEqual({ certificate_pem: "C2", chain_pem: "CH2" });
    });
    expect(ceremony.claimCertBegin).toHaveBeenCalledWith({ username: "o1", authenticator_type: "piv", slot: "9a" });
    expect(ceremony.claimCertComplete).toHaveBeenCalledWith({ username: "o1", nonce: "n1", signature: "sig" });
    expect(ceremony.claimShareBegin).toHaveBeenCalledWith({ username: "o1" });
    expect(ceremony.claimShareComplete).toHaveBeenCalledWith({ username: "o1", nonce: "n2", signature: "c2ln" });
    expect(ceremony.signCSR).toHaveBeenCalledWith({ username: "o1", so_pin: "1", csr_pem: "CSR", role: "admin" });
    expect(result.current.stepError).toBeNull();
  });

  it("a refused step returns null and keeps the server message", async () => {
    ceremony.signCSR.mockRejectedValue(new Error("csr required"));
    const { result } = renderHook(() => useCeremony());
    await waitFor(() => expect(result.current.status).not.toBeNull());
    let out: unknown = "unset";
    await act(async () => {
      out = await result.current.signCSR({ username: "o1", so_pin: "", csr_pem: "", role: "admin" });
    });
    expect(out).toBeNull();
    expect(result.current.stepError).toBe("csr required");
    expect(result.current.pending).toBeNull();
  });
});
