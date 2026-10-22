import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AddFactorWizard } from "./add-factor-wizard";
import { generateMTLSCredential } from "@/lib/csr";
import { authFactorsApi } from "@/utils/auth-factors-api";

vi.mock("@/lib/csr", () => ({ generateMTLSCredential: vi.fn() }));

const CSR_PEM = "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----\n";
const KEY_PEM = "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n";
const CERT_PEM = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n";

// Rotate mode opens the wizard straight on the mTLS step.
function renderMTLSStep() {
  render(
    <AddFactorWizard
      open
      onOpenChange={() => {}}
      userId="alice"
      onAdded={() => {}}
      rotateFactorId="factor-1"
      rotateFactorType="mtls"
    />
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AddFactorWizard mTLS generate", () => {
  it("sends a CSR for the user and offers the browser-held key for download", async () => {
    vi.mocked(generateMTLSCredential).mockResolvedValue({ csrPEM: CSR_PEM, privateKeyPEM: KEY_PEM });
    const issue = vi
      .spyOn(authFactorsApi, "issueMTLSCert")
      .mockResolvedValue({ ok: true, data: { cert_pem: CERT_PEM } });
    renderMTLSStep();

    fireEvent.click(screen.getByRole("button", { name: /generate certificate/i }));

    const keyLink = await screen.findByRole("link", { name: /download private key/i });
    expect(generateMTLSCredential).toHaveBeenCalledWith("alice");
    expect(issue).toHaveBeenCalledWith("alice", CSR_PEM);
    expect(decodeURIComponent(keyLink.getAttribute("href") ?? "")).toContain(KEY_PEM);
    const certLink = screen.getByRole("link", { name: /download certificate/i });
    expect(decodeURIComponent(certLink.getAttribute("href") ?? "")).toContain(CERT_PEM);
  });

  it("shows the handler's refusal and keeps no certificate", async () => {
    vi.mocked(generateMTLSCredential).mockResolvedValue({ csrPEM: CSR_PEM, privateKeyPEM: KEY_PEM });
    vi.spyOn(authFactorsApi, "issueMTLSCert").mockResolvedValue({
      ok: false,
      error: "CSR is not bound to the user",
      status: 403,
    });
    renderMTLSStep();

    fireEvent.click(screen.getByRole("button", { name: /generate certificate/i }));

    expect(await screen.findByText("CSR is not bound to the user")).toBeTruthy();
    expect(screen.queryByRole("link", { name: /download private key/i })).toBeNull();
    expect(screen.getByRole("button", { name: /generate certificate/i })).toBeTruthy();
  });
});
