import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { parsePCRList, pemToBase64DER, TPMKeyOperations } from "./key-operations";

// Codex round 2 on #1751: the EK certificate goes to the DER-only store as
// DER, a verified:false verdict is never announced as success, and Verify
// Quote sends the nonce of the quote it verifies.

const tpm = {
  quote: vi.fn(),
  verifyQuote: vi.fn(),
  importEKCertificate: vi.fn(),
  certify: vi.fn(),
  deleteAK: vi.fn(),
};
const toast = vi.fn();

vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  useTPM: () => tpm,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useTPM: () => tpm,
  useToast: () => ({ toast }),
}));

// The node quotes SHA-256(nonce || channelBinding) and echoes channelBinding
// (#482); the helpers below build such a quote, as in tpm/quote/page.test.tsx.
const callerBinding = new Uint8Array(32).fill(0xa1);
const relayBinding = new Uint8Array(32).fill(0xb2);

function b64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function unb64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}

/** A TPMS_ATTEST of type TPM_ST_ATTEST_QUOTE whose extraData is given. */
function attest(extraData: Uint8Array): Uint8Array {
  const out = new Uint8Array(10 + extraData.length + 17);
  const view = new DataView(out.buffer);
  view.setUint32(0, 0xff544347);
  view.setUint16(4, 0x8018);
  view.setUint16(6, 0);
  view.setUint16(8, extraData.length);
  out.set(extraData, 10);
  return out;
}

function boundTo(binding: Uint8Array) {
  return async (nonce: Uint8Array) =>
    new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([...nonce, ...binding])));
}

/** A quote answer over `quoted(nonce)`, echoing `echo` as the channel binding. */
function quoteAnswer(quoted: (nonce: Uint8Array) => Promise<Uint8Array>, echo?: Uint8Array) {
  return async (req: { nonce: string }) => ({
    success: true,
    data: {
      quote: b64(attest(await quoted(unb64(req.nonce)))),
      signature: "c2ln",
      signatureAlgorithm: "ECDSA-SHA256",
      ...(echo ? { channelBinding: b64(echo) } : {}),
    },
  });
}

const boundQuote = quoteAnswer(boundTo(callerBinding), callerBinding);

function click(testId: string) {
  fireEvent.click(screen.getByTestId(testId));
}

describe("TPMKeyOperations", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("pemToBase64DER returns the PEM body and null without markers", () => {
    expect(pemToBase64DER("-----BEGIN CERTIFICATE-----\nTUlJ\nQg==\n-----END CERTIFICATE-----\n")).toBe("TUlJQg==");
    expect(pemToBase64DER("TUlJQg==")).toBeNull();
    expect(pemToBase64DER("-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----")).toBeNull();
  });

  it("imports the EK certificate as base64 DER", async () => {
    tpm.importEKCertificate.mockResolvedValue({ success: true, data: { message: "imported" } });
    render(<TPMKeyOperations />);

    fireEvent.change(screen.getByLabelText("EK certificate (PEM)"), {
      target: { value: "-----BEGIN CERTIFICATE-----\nTUlJQg==\n-----END CERTIFICATE-----" },
    });
    click("tpm-op-importEKCertificate");

    await waitFor(() => expect(tpm.importEKCertificate).toHaveBeenCalledTimes(1));
    expect(tpm.importEKCertificate.mock.calls[0]?.[0]).toEqual({ certificate: "TUlJQg==", format: "DER" });
  });

  it("announces verified:false as an invalid quote, never as success", async () => {
    tpm.quote.mockImplementation(boundQuote);
    tpm.verifyQuote.mockResolvedValue({ success: true, data: { verified: false, message: "nonce mismatch" } });
    render(<TPMKeyOperations />);

    click("tpm-op-quote");
    await waitFor(() => expect(screen.getByTestId("tpm-op-verifyQuote")).toHaveProperty("disabled", false));
    click("tpm-op-verifyQuote");

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Quote INVALID", description: "nonce mismatch", variant: "destructive" }),
      ),
    );
    const descriptions = toast.mock.calls.map((c) => String((c[0] as { description?: unknown }).description));
    expect(descriptions.some((d) => d.includes("verifyQuote succeeded"))).toBe(false);
    expect(screen.getByTestId("tpm-verdict-verifyQuote").textContent).toContain("INVALID: nonce mismatch");
  });

  it("never verifies a retained quote with a failed attempt's nonce", async () => {
    tpm.quote.mockImplementationOnce(boundQuote);
    tpm.quote.mockResolvedValueOnce({ success: false, error: { message: "quote refused" } });
    tpm.verifyQuote.mockResolvedValue({ success: true, data: { verified: true, message: "ok" } });
    render(<TPMKeyOperations />);

    click("tpm-op-quote");
    await waitFor(() => expect(screen.getByTestId("tpm-op-verifyQuote")).toHaveProperty("disabled", false));
    const firstNonce = (tpm.quote.mock.calls[0]?.[0] as { nonce: string }).nonce;

    click("tpm-op-quote");
    await waitFor(() => expect(tpm.quote).toHaveBeenCalledTimes(2));
    await screen.findByTestId("tpm-error-quote");
    const secondNonce = (tpm.quote.mock.calls[1]?.[0] as { nonce: string }).nonce;
    expect(secondNonce).not.toBe(firstNonce);

    const verify = screen.getByTestId("tpm-op-verifyQuote") as HTMLButtonElement;
    if (verify.disabled) return;
    click("tpm-op-verifyQuote");
    await waitFor(() => expect(tpm.verifyQuote).toHaveBeenCalledTimes(1));
    expect((tpm.verifyQuote.mock.calls[0]?.[0] as { nonce: string }).nonce).toBe(firstNonce);
  });

  // Codex round 3 on #1751: Certify forwards the target key's password, and
  // DeleteAK shows the server's refusal to evict the platform AK.

  it("Certify sends the key password the operator typed", async () => {
    tpm.certify.mockResolvedValue({ success: true, data: { certifyInfo: "aW5mbw==" } });
    render(<TPMKeyOperations />);

    fireEvent.change(screen.getByLabelText("Key handle to certify"), { target: { value: "0x81000001" } });
    fireEvent.change(screen.getByLabelText("Key password (optional)"), { target: { value: "s3cret" } });
    click("tpm-op-certify");

    await waitFor(() => expect(tpm.certify).toHaveBeenCalledTimes(1));
    expect(tpm.certify.mock.calls[0]?.[0]).toMatchObject({ keyHandle: 0x81000001, keyPassword: "s3cret" });
  });

  it("Certify omits keyPassword when the password is blank", async () => {
    tpm.certify.mockResolvedValue({ success: true, data: { certifyInfo: "aW5mbw==" } });
    render(<TPMKeyOperations />);

    fireEvent.change(screen.getByLabelText("Key handle to certify"), { target: { value: "0x81000001" } });
    click("tpm-op-certify");

    await waitFor(() => expect(tpm.certify).toHaveBeenCalledTimes(1));
    const req = tpm.certify.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(req.keyHandle).toBe(0x81000001);
    expect("keyPassword" in req).toBe(false);
  });

  it("DeleteAK shows the server's refusal and never announces success", async () => {
    tpm.deleteAK.mockResolvedValue({
      success: false,
      error: { message: "idevid: the IAK key is TPM-resident and is not evicted by this service" },
    });
    render(<TPMKeyOperations />);

    click("tpm-op-deleteAK");
    expect(screen.getByTestId("tpm-confirm-dialog").textContent).toContain("refuses to evict");
    click("tpm-confirm-ok");

    await waitFor(() => expect(tpm.deleteAK).toHaveBeenCalledTimes(1));
    expect((await screen.findByTestId("tpm-error-deleteAK")).textContent).toContain("not evicted");
    expect(screen.queryByTestId("tpm-result-deleteAK")).toBeNull();
    expect(toast).not.toHaveBeenCalledWith(expect.objectContaining({ title: "Done" }));
  });

  // Codex round 4 on #1751: the quote must be bound to the nonce and the
  // echoed channel binding, a bad PCR list is refused before any request,
  // and the quote is always signed by the platform IAK.

  async function expectQuoteRefused() {
    await waitFor(() => expect(tpm.quote).toHaveBeenCalledTimes(1));
    await screen.findByTestId("tpm-error-quote");
    expect(screen.getByTestId("tpm-op-verifyQuote")).toHaveProperty("disabled", true);
    const descriptions = toast.mock.calls.map((c) => String((c[0] as { description?: unknown }).description));
    expect(descriptions.some((d) => d.includes("quote succeeded"))).toBe(false);
  }

  it("refuses a quote without a channel binding", async () => {
    tpm.quote.mockImplementation(quoteAnswer(async (nonce) => nonce));
    render(<TPMKeyOperations />);

    click("tpm-op-quote");
    await expectQuoteRefused();
  });

  it("refuses a quote bound to another binding", async () => {
    tpm.quote.mockImplementation(quoteAnswer(boundTo(relayBinding), callerBinding));
    render(<TPMKeyOperations />);

    click("tpm-op-quote");
    await expectQuoteRefused();
  });

  it.each(["0,7,11x", "0 7", "24", ""])("rejects malformed PCR input %j without a request", async (input) => {
    tpm.quote.mockImplementation(boundQuote);
    render(<TPMKeyOperations />);

    fireEvent.change(screen.getByLabelText("PCRs to quote"), { target: { value: input } });
    click("tpm-op-quote");

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Invalid PCR list", variant: "destructive" })),
    );
    expect(tpm.quote).not.toHaveBeenCalled();
  });

  it("quotes with the platform IAK whatever the AK handle field says", async () => {
    tpm.quote.mockImplementation(boundQuote);
    render(<TPMKeyOperations />);

    fireEvent.change(screen.getByLabelText("AK handle (Delete AK)"), { target: { value: "0x81010099" } });
    click("tpm-op-quote");

    await waitFor(() => expect(tpm.quote).toHaveBeenCalledTimes(1));
    expect(tpm.quote.mock.calls[0]?.[0]).toMatchObject({ akHandle: 0x81010002 });
    expect(screen.getByTestId("tpm-quote-key").textContent).toContain("platform IAK");
  });

  it("parsePCRList reads indices 0-23 and refuses anything else", () => {
    expect(parsePCRList("0, 1,7")).toEqual([0, 1, 7]);
    expect(parsePCRList("0,7,11x")).toBeNull();
    expect(parsePCRList("0 7")).toBeNull();
    expect(parsePCRList("")).toBeNull();
    expect(parsePCRList("24")).toBeNull();
  });
});
