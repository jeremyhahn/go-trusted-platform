import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import TPMSealPage from "./page";

// #1824: the page seals and unseals through the TPM service with the real
// useMutation hook; only the service and the toast are stubbed.

const tpm = {
  seal: vi.fn(),
  unseal: vi.fn(),
};
const toast = vi.fn();

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useTPM: () => tpm,
  useToast: () => ({ toast }),
}));

function sealButton(): HTMLButtonElement {
  return screen.getAllByRole("button", { name: /Seal Data/ }).find(
    (b) => b.getAttribute("role") !== "tab"
  ) as HTMLButtonElement;
}

function unsealButton(): HTMLButtonElement {
  return screen.getAllByRole("button", { name: /Unseal Data/ }).find(
    (b) => b.getAttribute("role") !== "tab"
  ) as HTMLButtonElement;
}

function fillSeal(cn: string, data: string) {
  fireEvent.change(screen.getByLabelText("Common Name"), { target: { value: cn } });
  fireEvent.change(screen.getByLabelText("Data to Seal"), { target: { value: data } });
}

function openUnseal() {
  fireEvent.mouseDown(screen.getByRole("tab", { name: /Unseal Data/ }), { button: 0 });
}

describe("TPMSealPage", () => {
  beforeEach(() => {
    tpm.seal.mockReset();
    tpm.unseal.mockReset();
    toast.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("binds to PCR 7 by default and needs a name and data to seal", () => {
    render(<TPMSealPage />);

    expect(screen.getByRole("checkbox", { name: /PCR 7/ }).getAttribute("aria-checked")).toBe("true");
    expect(screen.getByRole("checkbox", { name: /PCR 0/ }).getAttribute("aria-checked")).toBe("false");
    expect(sealButton().disabled).toBe(true);

    fireEvent.change(screen.getByLabelText("Common Name"), { target: { value: "disk-key" } });
    expect(sealButton().disabled).toBe(true);

    fireEvent.change(screen.getByLabelText("Data to Seal"), { target: { value: "secret" } });
    expect(sealButton().disabled).toBe(false);
  });

  it("refuses to seal with no PCR selected", () => {
    render(<TPMSealPage />);
    fillSeal("disk-key", "secret");

    fireEvent.click(screen.getByRole("checkbox", { name: /PCR 7/ }));

    expect(sealButton().disabled).toBe(true);
  });

  it("seals the base64 data to the selected PCRs in order and shows the blob", async () => {
    tpm.seal.mockResolvedValue({ data: { sealedData: "c2VhbGVkLWJsb2I=" } });
    render(<TPMSealPage />);
    fillSeal("disk-key", "secret");
    fireEvent.click(screen.getByRole("checkbox", { name: /PCR 9/ }));
    fireEvent.click(screen.getByRole("checkbox", { name: /PCR 0/ }));

    fireEvent.click(sealButton());

    expect(await screen.findByDisplayValue("c2VhbGVkLWJsb2I=")).toBeTruthy();
    expect(tpm.seal).toHaveBeenCalledWith({ data: btoa("secret"), cn: "disk-key", pcrIndices: [0, 7, 9] });
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Data sealed successfully", description: "Data has been sealed with CN: disk-key" })
    );
  });

  it("shows nothing when the seal response carries no blob", async () => {
    tpm.seal.mockResolvedValue({ data: {} });
    render(<TPMSealPage />);
    fillSeal("disk-key", "secret");

    fireEvent.click(sealButton());

    await waitFor(() => expect(tpm.seal).toHaveBeenCalledTimes(1));
    expect(screen.queryByText("Sealed Data (Base64)")).toBeNull();
    expect(toast).not.toHaveBeenCalled();
  });

  it("toasts a seal error from the server", async () => {
    tpm.seal.mockResolvedValue({ error: { message: "policy session failed", code: 500 } });
    render(<TPMSealPage />);
    fillSeal("disk-key", "secret");

    fireEvent.click(sealButton());

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error sealing data", description: "policy session failed", variant: "destructive" })
      )
    );
    expect(screen.queryByText("Sealed Data (Base64)")).toBeNull();
  });

  // Every existing seal holds Latin-1 bytes and carries no encoding marker, so
  // the page keeps that encoding and refuses what it cannot encode, with a toast.
  it("refuses text above U+00FF with an error and seals nothing", async () => {
    render(<TPMSealPage />);
    fillSeal("disk-key", "price: 5 €");

    fireEvent.click(sealButton());

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error sealing data", variant: "destructive" })
      )
    );
    expect(tpm.seal).not.toHaveBeenCalled();
  });

  it("seals Latin-1 text byte for byte", async () => {
    tpm.seal.mockResolvedValue({ data: { sealedData: "YmxvYg==" } });
    render(<TPMSealPage />);
    fillSeal("disk-key", "café");

    fireEvent.click(sealButton());

    await waitFor(() => expect(tpm.seal).toHaveBeenCalledTimes(1));
    expect(tpm.seal.mock.calls[0]?.[0].data).toBe(btoa("café"));
  });

  it("needs a name to unseal", () => {
    render(<TPMSealPage />);
    openUnseal();

    expect(unsealButton().disabled).toBe(true);
  });

  it("unseals by name with the selected PCRs and shows the decoded data", async () => {
    tpm.unseal.mockResolvedValue({ data: { data: btoa("secret") } });
    render(<TPMSealPage />);
    openUnseal();

    fireEvent.change(await screen.findByLabelText("Common Name"), { target: { value: "disk-key" } });
    fireEvent.click(unsealButton());

    expect(await screen.findByDisplayValue("secret")).toBeTruthy();
    expect(tpm.unseal).toHaveBeenCalledWith({ cn: "disk-key", pcrIndices: [7] });
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Data unsealed successfully" }));
  });

  it("unseals bytes that are also valid UTF-8 one char per byte, never guessing", async () => {
    // C3 A9 is "é" in UTF-8 but two Latin-1 chars; the page must show the latter.
    tpm.unseal.mockResolvedValue({ data: { data: Buffer.from([0x63, 0x61, 0x66, 0xc3, 0xa9]).toString("base64") } });
    render(<TPMSealPage />);
    openUnseal();

    fireEvent.change(await screen.findByLabelText("Common Name"), { target: { value: "disk-key" } });
    fireEvent.click(unsealButton());

    expect(await screen.findByDisplayValue("cafÃ©")).toBeTruthy();
    expect(screen.queryByDisplayValue("café")).toBeNull();
  });

  it("decodes a secret sealed by the old Latin-1 encoder byte for byte", async () => {
    // The previous encoder stored btoa(sealData): one byte per char, so "é" is E9, not UTF-8.
    tpm.unseal.mockResolvedValue({ data: { data: btoa("café") } });
    render(<TPMSealPage />);
    openUnseal();

    fireEvent.change(await screen.findByLabelText("Common Name"), { target: { value: "disk-key" } });
    fireEvent.click(unsealButton());

    expect(await screen.findByDisplayValue("café")).toBeTruthy();
  });

  it("shows nothing when the unseal response carries no data", async () => {
    tpm.unseal.mockResolvedValue({ data: {} });
    render(<TPMSealPage />);
    openUnseal();

    fireEvent.change(await screen.findByLabelText("Common Name"), { target: { value: "disk-key" } });
    fireEvent.click(unsealButton());

    await waitFor(() => expect(tpm.unseal).toHaveBeenCalledTimes(1));
    expect(screen.queryByText("Unsealed Data")).toBeNull();
    expect(toast).not.toHaveBeenCalled();
  });

  it("toasts an unseal error, such as a PCR mismatch", async () => {
    tpm.unseal.mockRejectedValue(new Error("PCR policy mismatch"));
    render(<TPMSealPage />);
    openUnseal();

    fireEvent.change(await screen.findByLabelText("Common Name"), { target: { value: "disk-key" } });
    fireEvent.click(unsealButton());

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error unsealing data", description: "PCR policy mismatch", variant: "destructive" })
      )
    );
    expect(screen.queryByText("Unsealed Data")).toBeNull();
  });
});
