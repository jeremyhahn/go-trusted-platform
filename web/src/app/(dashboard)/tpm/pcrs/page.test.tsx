import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import TPMPCRsPage from "./page";

// #1824: the page reads the PCR bank through the real useApi hook; only the
// TPM service and the toast are stubbed.

const tpm = {
  getPCRs: vi.fn(),
};
const toast = vi.fn();

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useTPM: () => tpm,
  useToast: () => ({ toast }),
}));

function b64(bytes: number[]): string {
  return btoa(String.fromCharCode(...bytes));
}

const zero = b64(new Array(32).fill(0));
const measured = b64([0xde, 0xad, 0xbe, 0xef]);

function bank(values: { index: number; value: string }[]) {
  return { data: { pcrValues: values } };
}

/** The text of the stat card whose title is given. */
function card(title: string): string {
  return screen.getByText(title).parentElement?.parentElement?.textContent ?? "";
}

// floating-ui and Radix Select need these in jsdom (see
// components/layout/account-identity.test.tsx for the `:modal` probe).
const nativeMatches = Element.prototype.matches;

describe("TPMPCRsPage", () => {
  const writeText = vi.fn();

  beforeAll(() => {
    Element.prototype.matches = function (this: Element, selector: string) {
      return selector === ":modal" ? false : nativeMatches.call(this, selector);
    };
    Element.prototype.scrollIntoView = vi.fn();
    Element.prototype.hasPointerCapture = vi.fn(() => false);
    Element.prototype.releasePointerCapture = vi.fn();
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
  });

  afterAll(() => {
    Element.prototype.matches = nativeMatches;
  });

  beforeEach(() => {
    tpm.getPCRs.mockReset();
    toast.mockReset();
    writeText.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("requests all 24 PCRs of the SHA-256 bank and renders them in hex", async () => {
    tpm.getPCRs.mockResolvedValue(
      bank([
        { index: 0, value: zero },
        { index: 7, value: measured },
        { index: 30, value: measured },
      ])
    );
    render(<TPMPCRsPage />);

    expect(await screen.findAllByText("deadbeef")).toHaveLength(2);
    expect(tpm.getPCRs).toHaveBeenCalledWith({
      indices: Array.from({ length: 24 }, (_, i) => i),
      bank: "SHA256",
    });
    expect(screen.getByText("0".repeat(64))).toBeTruthy();
    expect(screen.getByText("Secure Boot policy")).toBeTruthy();
    expect(screen.getByText("Reserved")).toBeTruthy();
    expect(screen.getAllByText("Active")).toHaveLength(2);
    expect(card("Total PCRs")).toContain("3");
    expect(card("Measured PCRs")).toContain("2");
    expect(card("Unused PCRs")).toContain("1");
  });

  it("counts an empty value as zero", async () => {
    tpm.getPCRs.mockResolvedValue(bank([{ index: 16, value: "" }]));
    render(<TPMPCRsPage />);

    expect(await screen.findByText("Application support (debug)")).toBeTruthy();
    expect(screen.queryByText("Active")).toBeNull();
    expect(card("Unused PCRs")).toContain("1");
  });

  it("says when the bank has no values", async () => {
    tpm.getPCRs.mockResolvedValue(bank([]));
    render(<TPMPCRsPage />);

    expect(await screen.findByText("No PCR bank data available for SHA256")).toBeTruthy();
    expect(card("Total PCRs")).toContain("0");
  });

  it("shows the server error and toasts it", async () => {
    tpm.getPCRs.mockResolvedValue({ error: { message: "bank SHA256 not allocated" } });
    render(<TPMPCRsPage />);

    expect(await screen.findByText("bank SHA256 not allocated")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Error loading PCRs", description: "bank SHA256 not allocated", variant: "destructive" })
    );
    expect(screen.getByText("No PCR bank data available for SHA256")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /Copy All/ }));
    expect(writeText).not.toHaveBeenCalled();
  });

  it("copies one PCR in hex and every PCR as listed", async () => {
    tpm.getPCRs.mockResolvedValue(bank([{ index: 0, value: zero }, { index: 7, value: measured }]));
    render(<TPMPCRsPage />);
    const row = (await screen.findByText("deadbeef")).closest("tr");

    // The last button of the row copies; the first is the tooltip trigger.
    const copy = row?.querySelector("td:last-child button");
    if (!copy) throw new Error("no copy button");
    fireEvent.click(copy);
    expect(writeText).toHaveBeenLastCalledWith("deadbeef");
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Copied to clipboard", variant: "success" }));

    fireEvent.click(screen.getByRole("button", { name: /Copy All/ }));
    expect(writeText).toHaveBeenLastCalledWith(`PCR[0]: ${zero}\nPCR[7]: ${measured}`);
  });

  it("fetches the bank the operator selects", async () => {
    tpm.getPCRs.mockResolvedValue(bank([{ index: 7, value: measured }]));
    render(<TPMPCRsPage />);
    await screen.findByText("deadbeef");

    fireEvent.keyDown(screen.getByRole("combobox"), { key: "Enter" });
    fireEvent.keyDown(await screen.findByRole("option", { name: "SHA-1" }), { key: "Enter" });

    await waitFor(() => expect(tpm.getPCRs).toHaveBeenLastCalledWith(expect.objectContaining({ bank: "SHA1" })));
    expect(await screen.findByText("PCR Values - SHA1")).toBeTruthy();
  });

  it("fetches the bank again on Refresh", async () => {
    tpm.getPCRs.mockResolvedValue(bank([{ index: 7, value: measured }]));
    render(<TPMPCRsPage />);
    await screen.findByText("deadbeef");

    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));

    await waitFor(() => expect(tpm.getPCRs).toHaveBeenCalledTimes(2));
  });
});
