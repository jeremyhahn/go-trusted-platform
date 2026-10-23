import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import TPMQuotePage from "./page";

// #482: the node quotes SHA-256(nonce || channelBinding), the TLS exporter of
// the connection the request arrived on, and returns channelBinding with the
// quote. The page refuses any other quote — the bare nonce a relay oracle
// produced, or a quote bound to the relay's connection under a rewritten
// echo — and sends the binding to verify, where a bound quote needs it.

const tpm = {
  quote: vi.fn(),
  verifyQuote: vi.fn(),
};

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useTPM: () => tpm,
  useToast: () => ({ toast: vi.fn() }),
}));

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

/**
 * A node answering /tpm/quote: it quotes `quoted(nonce)` and echoes `echo`
 * as the channel binding.
 */
function node(quoted: (nonce: Uint8Array) => Promise<Uint8Array>, echo?: Uint8Array) {
  tpm.quote.mockImplementation(async (req: { nonce: string }) => ({
    success: true,
    data: {
      quote: b64(attest(await quoted(unb64(req.nonce)))),
      signature: "c2ln",
      signatureAlgorithm: "SHA256-RSAPSS",
      ...(echo ? { channelBinding: b64(echo) } : {}),
    },
  }));
}

function boundTo(binding: Uint8Array) {
  return async (nonce: Uint8Array) =>
    new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array([...nonce, ...binding])));
}

function generate() {
  fireEvent.click(screen.getByRole("button", { name: /Generate Quote/ }));
}

describe("TPMQuotePage channel binding", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("accepts the quote bound to its channel binding and verifies with it", async () => {
    node(boundTo(callerBinding), callerBinding);
    tpm.verifyQuote.mockResolvedValue({ success: true, data: { verified: true } });
    render(<TPMQuotePage />);

    generate();
    await waitFor(() => expect(screen.getByLabelText(/Channel binding/)).toHaveProperty("value", b64(callerBinding)));
    fireEvent.click(screen.getByRole("button", { name: /Verify Quote/ }));

    await waitFor(() => expect(tpm.verifyQuote).toHaveBeenCalledTimes(1));
    expect(tpm.verifyQuote.mock.calls[0]?.[0]).toMatchObject({ channelBinding: b64(callerBinding) });
    expect(await screen.findByText("VERIFIED")).toBeTruthy();
  });

  // The signature is checked under the scheme the quote declared, so the
  // verify panel carries it over from the quote (#482).
  it("verifies under the scheme the quote declared", async () => {
    node(boundTo(callerBinding), callerBinding);
    tpm.verifyQuote.mockResolvedValue({ success: true, data: { verified: true } });
    render(<TPMQuotePage />);

    generate();
    await waitFor(() => expect(screen.getByLabelText(/Signature scheme/)).toHaveProperty("value", "SHA256-RSAPSS"));
    fireEvent.click(screen.getByRole("button", { name: /Verify Quote/ }));

    await waitFor(() => expect(tpm.verifyQuote).toHaveBeenCalledTimes(1));
    expect(tpm.verifyQuote.mock.calls[0]?.[0]).toMatchObject({ signatureAlgorithm: "SHA256-RSAPSS" });
  });

  it("refuses a quote of the bare nonce", async () => {
    node(async (nonce) => nonce);
    render(<TPMQuotePage />);

    generate();

    expect(await screen.findByText(/no channel binding/)).toBeTruthy();
    expect(screen.getByLabelText(/Channel binding/)).toHaveProperty("value", "");
  });

  it("refuses a relayed quote under a rewritten echo", async () => {
    node(boundTo(relayBinding), callerBinding);
    render(<TPMQuotePage />);

    generate();

    expect(await screen.findByText(/not bound to the nonce and channel binding/)).toBeTruthy();
    expect(screen.getByLabelText("Attestation")).toHaveProperty("value", "");
    expect(screen.getByLabelText(/Channel binding/)).toHaveProperty("value", "");
  });
});
