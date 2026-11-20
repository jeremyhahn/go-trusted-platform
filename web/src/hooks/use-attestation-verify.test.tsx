import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useAttestationVerify } from "./use-attestation-verify";

// #2038: VerifyManifest, GetAttestationQuote and VerifyAttestationQuote from
// the web console, through the SDK client only.

const service = {
  verifyManifest: vi.fn(),
  getQuote: vi.fn(),
  verifyQuote: vi.fn(),
};

vi.mock("trusted-platform-sdk", () => ({
  useAttestation: () => service,
}));

const manifest = { id: "m-1", hostId: "h-1", timestamp: "t", nonce: "bg==", vms: [] };
const quote = { quoteData: "cQ==", signature: "cw==", signatureAlgorithm: "ECDSA-SHA256", pcrValues: [] };

describe("useAttestationVerify", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("verifies a manifest and keeps the server's result", async () => {
    service.verifyManifest.mockResolvedValue({
      success: true,
      data: { status: { success: true, message: "ok" }, result: { status: "VALID" } },
    });
    const { result } = renderHook(() => useAttestationVerify());

    let ok = false;
    await act(async () => {
      ok = await result.current.verifyManifest(manifest as never);
    });

    expect(ok).toBe(true);
    expect(service.verifyManifest).toHaveBeenCalledWith({ manifest });
    expect(result.current.manifest.result?.result?.status).toBe("VALID");
    expect(result.current.manifest.error).toBeUndefined();
  });

  it("reports a failed manifest status as an error", async () => {
    service.verifyManifest.mockResolvedValue({
      success: true,
      data: { status: { success: false, message: "bad signature" } },
    });
    const { result } = renderHook(() => useAttestationVerify());

    await act(async () => {
      await result.current.verifyManifest(manifest as never);
    });

    expect(result.current.manifest.error).toBe("bad signature");
  });

  it("gets a quote with a fresh nonce and verifies it with that nonce and binding", async () => {
    service.getQuote.mockResolvedValue({
      success: true,
      data: { status: { success: true, message: "" }, quote, channelBinding: "Ymk=" },
    });
    service.verifyQuote.mockResolvedValue({
      success: true,
      data: { status: { success: true, message: "" }, verified: false, message: "signature mismatch" },
    });
    const { result } = renderHook(() => useAttestationVerify());

    await act(async () => {
      await result.current.getQuote();
    });
    const sent = service.getQuote.mock.calls[0][0];
    expect(sent.config).toEqual({});
    expect(sent.nonce).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(result.current.quote.result?.quote).toEqual(quote);

    await act(async () => {
      await result.current.verifyQuote("PEM");
    });
    expect(service.verifyQuote).toHaveBeenCalledWith({
      quote,
      akPublicKeyPem: "PEM",
      expectedNonce: sent.nonce,
      channelBinding: "Ymk=",
    });
    expect(result.current.verdict.result?.verified).toBe(false);
    expect(result.current.verdict.result?.message).toBe("signature mismatch");
  });

  it("refuses to verify before a quote is held and calls no SDK method", async () => {
    const { result } = renderHook(() => useAttestationVerify());

    let ok = true;
    await act(async () => {
      ok = await result.current.verifyQuote("PEM");
    });

    expect(ok).toBe(false);
    expect(service.verifyQuote).not.toHaveBeenCalled();
    expect(result.current.verdict.error).toContain("Get a quote first");
  });

  it("marks the quote control unavailable when the server has no TPM", async () => {
    service.getQuote.mockResolvedValue({
      success: false,
      error: { status: 503, message: "attestation service unavailable" },
    });
    const { result } = renderHook(() => useAttestationVerify());

    await act(async () => {
      await result.current.getQuote();
    });

    expect(result.current.quote.unavailable).toBe(true);
    expect(result.current.quote.error).toBe("attestation service unavailable");
  });
});
