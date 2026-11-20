import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import TPMIDevIDPage from "./page";

// #2055: the IDevID and IAK page drives the 12 IDevIDService operations of
// coverage-matrix slice 18 through the SDK client returned by useIDevID.

const idevid = {
  hasIDevID: vi.fn(),
  hasIAK: vi.fn(),
  getDeviceAttributes: vi.fn(),
  generateIAK: vi.fn(),
  deleteIAK: vi.fn(),
  createIAKCSR: vi.fn(),
  createLDevID: vi.fn(),
  installIDevIDCertificate: vi.fn(),
  installIAKCertificate: vi.fn(),
  deleteIAKCertificate: vi.fn(),
  flushTransientContexts: vi.fn(),
  activateCredential: vi.fn(),
};
const toast = vi.fn();

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useIDevID: () => idevid,
  useToast: () => ({ toast }),
}));

const PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";

function seedStatus() {
  idevid.hasIDevID.mockResolvedValue({ data: { exists: false } });
  idevid.hasIAK.mockResolvedValue({ data: { exists: true } });
  idevid.getDeviceAttributes.mockResolvedValue({
    data: { attributes: { tpmManufacturer: "IFX", platformSerial: "SN-42" } },
  });
}

async function confirm(label: string) {
  fireEvent.click(screen.getByRole("button", { name: label }));
  fireEvent.click(await screen.findByRole("button", { name: "Confirm" }));
}

describe("TPMIDevIDPage", () => {
  beforeEach(() => {
    Object.values(idevid).forEach((fn) => fn.mockReset());
    toast.mockReset();
    seedStatus();
  });

  afterEach(() => {
    cleanup();
  });

  it("shows the IDevID and IAK presence and the device attributes", async () => {
    render(<TPMIDevIDPage />);

    await waitFor(() => expect(screen.getByTestId("iak-status").textContent).toBe("Present"));
    expect(screen.getByTestId("idevid-status").textContent).toBe("Absent");
    await waitFor(() => expect(screen.getByTestId("device-attributes").textContent).toContain("IFX"));
    expect(screen.getByTestId("device-attributes").textContent).toContain("SN-42");
  });

  it("shows a status load error on the page, not only in a toast", async () => {
    idevid.hasIAK.mockResolvedValue({ error: { message: "iak lookup failed" } });
    render(<TPMIDevIDPage />);

    expect(await screen.findByText("iak lookup failed")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Error loading IAK status", variant: "destructive" })
    );
  });

  it("generates the IAK and reloads the status", async () => {
    idevid.generateIAK.mockResolvedValue({ data: {} });
    render(<TPMIDevIDPage />);
    await waitFor(() => expect(idevid.hasIAK).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole("button", { name: "Generate IAK" }));

    await waitFor(() => expect(idevid.generateIAK).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(idevid.hasIAK).toHaveBeenCalledTimes(2));
  });

  it("keeps the TCG_CSR_IDEVID base64 when it is not PEM", async () => {
    idevid.createIAKCSR.mockResolvedValue({ data: { csrPem: "AAECAw==" } });
    render(<TPMIDevIDPage />);

    fireEvent.click(screen.getByRole("button", { name: "Create IAK CSR" }));

    const result = await screen.findByTestId("idevid-result");
    expect(result.textContent).toContain("IAK CSR created");
    expect(result.querySelector("pre")?.textContent).toBe("AAECAw==");
  });

  it("creates an LDevID with the common name and shows the decoded PEM", async () => {
    idevid.createLDevID.mockResolvedValue({ data: { certificatePem: btoa(PEM) } });
    render(<TPMIDevIDPage />);

    fireEvent.change(screen.getByLabelText("LDevID common name"), { target: { value: "dev-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Create LDevID" }));

    await waitFor(() =>
      expect(idevid.createLDevID).toHaveBeenCalledWith({ template: { commonName: "dev-1" } })
    );
    const result = await screen.findByTestId("idevid-result");
    expect(result.querySelector("pre")?.textContent).toContain("BEGIN CERTIFICATE");
  });

  it("installs the IDevID and IAK certificates as base64 PEM", async () => {
    idevid.installIDevIDCertificate.mockResolvedValue({ data: {} });
    idevid.installIAKCertificate.mockResolvedValue({ data: {} });
    render(<TPMIDevIDPage />);

    fireEvent.change(screen.getByLabelText("IDevID certificate (PEM)"), { target: { value: PEM } });
    fireEvent.click(screen.getByRole("button", { name: "Install IDevID certificate" }));
    await waitFor(() =>
      expect(idevid.installIDevIDCertificate).toHaveBeenCalledWith({ certificatePem: btoa(PEM) })
    );

    fireEvent.change(screen.getByLabelText("IAK certificate (PEM)"), { target: { value: PEM } });
    fireEvent.click(screen.getByRole("button", { name: "Install IAK certificate" }));
    await waitFor(() =>
      expect(idevid.installIAKCertificate).toHaveBeenCalledWith({ certificatePem: btoa(PEM) })
    );
  });

  it("deletes the IAK and the IAK certificate only after confirmation", async () => {
    idevid.deleteIAK.mockResolvedValue({ error: { message: "the IAK is TPM-resident" } });
    idevid.deleteIAKCertificate.mockResolvedValue({ data: {} });
    render(<TPMIDevIDPage />);

    await confirm("Delete IAK");
    await waitFor(() => expect(idevid.deleteIAK).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error deleting IAK" }))
    );

    await confirm("Delete IAK certificate");
    await waitFor(() => expect(idevid.deleteIAKCertificate).toHaveBeenCalledTimes(1));
  });

  it("flushes transient contexts and shows the count", async () => {
    idevid.flushTransientContexts.mockResolvedValue({ data: { flushedCount: 3 } });
    render(<TPMIDevIDPage />);

    await confirm("Flush transient contexts");

    const result = await screen.findByTestId("idevid-result");
    expect(result.textContent).toContain("Flushed 3 contexts");
  });

  it("activates a credential with the blob and the secret", async () => {
    idevid.activateCredential.mockResolvedValue({ data: { decryptedSecret: "c2VjcmV0" } });
    render(<TPMIDevIDPage />);

    const button = screen.getByRole("button", { name: "Activate credential" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Credential blob (base64)"), { target: { value: "YmxvYg==" } });
    fireEvent.change(screen.getByLabelText("Encrypted secret (base64)"), { target: { value: "c2Vj" } });
    fireEvent.click(button);

    await waitFor(() =>
      expect(idevid.activateCredential).toHaveBeenCalledWith({ credentialBlob: "YmxvYg==", secret: "c2Vj" })
    );
    expect((await screen.findByTestId("idevid-result")).textContent).toContain("c2VjcmV0");
  });
});
