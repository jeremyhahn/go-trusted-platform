import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import TPMLockoutPage from "./page";

// #1824: the page reads the dictionary-attack state from the capabilities of
// GET /api/v1/tpm/info through the real useApi hook.

const tpm = {
  getInfo: vi.fn(),
};
const toast = vi.fn();

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useTPM: () => tpm,
  useToast: () => ({ toast }),
}));

function info(caps: Record<string, string>) {
  return {
    data: {
      capabilities: Object.entries(caps).map(([name, value]) => ({ name, value })),
    },
  };
}

/** The text of the card whose title is given. */
function card(title: string): string {
  return screen.getByText(title).parentElement?.parentElement?.textContent ?? "";
}

describe("TPMLockoutPage", () => {
  beforeEach(() => {
    tpm.getInfo.mockReset();
    toast.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("shows an operational TPM below the failure threshold", async () => {
    tpm.getInfo.mockResolvedValue(
      info({ lockoutCounter: "2", maxAuthFail: "10", lockoutInterval: "7200", lockoutRecovery: "86400" })
    );
    render(<TPMLockoutPage />);

    expect(await screen.findByText("Operational")).toBeTruthy();
    expect(screen.getByText("Auth counter below failure threshold")).toBeTruthy();
    expect(card("Counter")).toContain("2 / 10");
    expect(card("Counter")).toContain("(20%)");
    expect(card("Tick Interval")).toContain("2h");
    expect(card("Recovery Interval")).toContain("1d");
  });

  it("shows a TPM at the threshold as locked out", async () => {
    tpm.getInfo.mockResolvedValue(info({ lockoutCounter: "10", maxAuthFail: "10" }));
    render(<TPMLockoutPage />);

    expect(await screen.findByText("Locked Out")).toBeTruthy();
    expect(screen.getByText(/Failed auth threshold reached/)).toBeTruthy();
    expect(card("Counter")).toContain("(100%)");
  });

  it("caps the utilization at 100% when the counter passes the threshold", async () => {
    tpm.getInfo.mockResolvedValue(info({ lockoutCounter: "15", maxAuthFail: "10" }));
    render(<TPMLockoutPage />);

    expect(await screen.findByText("Locked Out")).toBeTruthy();
    expect(card("Counter")).toContain("15 / 10");
    expect(card("Counter")).toContain("(100%)");
  });

  it("formats seconds and minutes", async () => {
    tpm.getInfo.mockResolvedValue(
      info({ lockoutCounter: "0", maxAuthFail: "32", lockoutInterval: "45", lockoutRecovery: "120" })
    );
    render(<TPMLockoutPage />);

    expect(await screen.findByText("Operational")).toBeTruthy();
    expect(card("Tick Interval")).toContain("45s");
    expect(card("Recovery Interval")).toContain("2m");
    expect(card("Counter")).toContain("(0%)");
  });

  it("treats missing capabilities as zero and never locks out without a threshold", async () => {
    tpm.getInfo.mockResolvedValue({ data: {} });
    render(<TPMLockoutPage />);

    expect(await screen.findByText("Operational")).toBeTruthy();
    expect(card("Counter")).toContain("0 / 0");
    expect(card("Counter")).toContain("(0%)");
    expect(card("Tick Interval")).toContain("0");
  });

  it("treats a non-numeric capability as zero", async () => {
    tpm.getInfo.mockResolvedValue(
      info({ lockoutCounter: "many", maxAuthFail: "ten", lockoutInterval: "soon", lockoutRecovery: "" })
    );
    render(<TPMLockoutPage />);

    expect(await screen.findByText("Operational")).toBeTruthy();
    expect(screen.queryByText(/NaN/)).toBeNull();
    expect(card("Counter")).toContain("0 / 0");
    expect(card("Tick Interval")).toContain("0");
  });

  it("shows the server error, toasts it and renders no state", async () => {
    tpm.getInfo.mockResolvedValue({ error: { message: "tpm service is not available" } });
    render(<TPMLockoutPage />);

    expect(await screen.findByText("tpm service is not available")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Error loading TPM info",
        description: "tpm service is not available",
        variant: "destructive",
      })
    );
    expect(screen.queryByText("Lockout State")).toBeNull();
  });

  it("fetches the state again on Refresh", async () => {
    tpm.getInfo.mockResolvedValue(info({ lockoutCounter: "0", maxAuthFail: "3" }));
    render(<TPMLockoutPage />);
    expect(await screen.findByText("Operational")).toBeTruthy();

    tpm.getInfo.mockResolvedValue(info({ lockoutCounter: "3", maxAuthFail: "3" }));
    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));

    expect(await screen.findByText("Locked Out")).toBeTruthy();
    await waitFor(() => expect(tpm.getInfo).toHaveBeenCalledTimes(2));
  });
});
