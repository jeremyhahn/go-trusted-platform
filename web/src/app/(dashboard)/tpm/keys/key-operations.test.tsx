import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { pemToBase64DER, TPMKeyOperations } from "./key-operations";

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

const QUOTE = { quote: "cXVvdGU=", signature: "c2ln", signatureAlgorithm: "ECDSA-SHA256", channelBinding: "Y2I=" };

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
    tpm.quote.mockResolvedValue({ success: true, data: QUOTE });
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
    tpm.quote.mockResolvedValueOnce({ success: true, data: QUOTE });
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
});
