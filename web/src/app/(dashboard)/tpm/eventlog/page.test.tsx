import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import TPMEventLogPage from "./page";

// #1824: the page renders GET /api/v1/tpm/eventlog through the real useApi
// hook; only the TPM service and the toast are stubbed.

const tpm = {
  getEventLog: vi.fn(),
};
const toast = vi.fn();

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useTPM: () => tpm,
  useToast: () => ({ toast }),
}));

function entry(pcrIndex: number, eventType?: string, eventString?: string) {
  return { pcrIndex, eventType, eventString };
}

/** The text of the stat card whose title is given. */
function card(title: string): string {
  return screen.getByText(title).parentElement?.parentElement?.textContent ?? "";
}

describe("TPMEventLogPage", () => {
  beforeEach(() => {
    tpm.getEventLog.mockReset();
    toast.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("renders parsed entries with the PCR label, type and data", async () => {
    tpm.getEventLog.mockResolvedValue({
      data: {
        entries: [
          entry(0, "EV_S_CRTM_VERSION", "crtm"),
          entry(7, "EV_EFI_VARIABLE_DRIVER_CONFIG", "SecureBoot"),
          entry(7, "EV_SEPARATOR", "sep"),
        ],
        format: "tcg2",
      },
    });
    render(<TPMEventLogPage />);

    expect(await screen.findByText("EV_S_CRTM_VERSION")).toBeTruthy();
    expect(screen.getByText("BIOS/UEFI code")).toBeTruthy();
    expect(screen.getAllByText("Secure Boot policy")).toHaveLength(2);
    expect(screen.getByText("SecureBoot")).toBeTruthy();
    expect(card("Total Events")).toContain("3");
    expect(card("PCRs Measured")).toContain("2");
    expect(screen.getByText("Crypto-agile TCG 2.0 log (multiple banks)")).toBeTruthy();
    expect(screen.queryByText(/Showing first 200/)).toBeNull();
  });

  it("shows a dash for an unlabelled PCR and a missing type or data", async () => {
    tpm.getEventLog.mockResolvedValue({ data: { entries: [entry(17)] } });
    render(<TPMEventLogPage />);

    expect(await screen.findByText("PCR 17")).toBeTruthy();
    expect(screen.getAllByText("—")).toHaveLength(3);
  });

  it("shows the first 200 entries and says how many there are", async () => {
    const entries = Array.from({ length: 205 }, (_, i) => entry(4, `EV_${i}`));
    tpm.getEventLog.mockResolvedValue({ data: { entries } });
    render(<TPMEventLogPage />);

    expect(await screen.findByText("EV_199")).toBeTruthy();
    expect(screen.queryByText("EV_200")).toBeNull();
    expect(screen.getByText(/Showing first 200 of 205 events/)).toBeTruthy();
    expect(card("Total Events")).toContain("205");
  });

  it("explains a raw log without parsed entries and downloads it", async () => {
    const createObjectURL = vi.fn(() => "blob:eventlog");
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    tpm.getEventLog.mockResolvedValue({
      data: { eventLog: btoa("\x00\x01raw"), eventCount: 42, format: "tcg1" },
    });
    render(<TPMEventLogPage />);

    expect(await screen.findByText(/Server reports/)).toBeTruthy();
    expect(screen.getByText(/parsing is not yet implemented/)).toBeTruthy();
    expect(screen.getByText("Legacy SHA-1-only TCG 1.2 log")).toBeTruthy();
    expect(card("Total Events")).toContain("42");

    fireEvent.click(screen.getByRole("button", { name: /Download \.bin/ }));

    expect(createObjectURL).toHaveBeenCalledTimes(1);
    const blob = (createObjectURL.mock.calls[0] as unknown[])[0] as Blob;
    expect(blob.size).toBe(5);
    expect(click).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:eventlog");
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Event log downloaded", variant: "success" })
    );
    expect(toast.mock.calls[0]?.[0].description).toContain("tcg1");
    click.mockRestore();
  });

  it("shows the empty state without a download button for an empty log", async () => {
    tpm.getEventLog.mockResolvedValue({ data: {} });
    render(<TPMEventLogPage />);

    expect(await screen.findByText("No event log entries available.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Download/ })).toBeNull();
    expect(card("Total Events")).toContain("0");
    expect(card("Format")).toContain("tcg2");
  });

  it("shows the server error and toasts it", async () => {
    tpm.getEventLog.mockResolvedValue({ error: { message: "tpm service is not available" } });
    render(<TPMEventLogPage />);

    expect(await screen.findByText("tpm service is not available")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Error loading event log",
        description: "tpm service is not available",
        variant: "destructive",
      })
    );
  });

  it("shows a thrown error", async () => {
    tpm.getEventLog.mockRejectedValue(new Error("network down"));
    render(<TPMEventLogPage />);

    expect(await screen.findByText("network down")).toBeTruthy();
    expect(toast).toHaveBeenCalledTimes(1);
  });

  it("fetches the log again on Refresh", async () => {
    tpm.getEventLog.mockResolvedValue({ data: { entries: [entry(9, "EV_IPL")] } });
    render(<TPMEventLogPage />);
    expect(await screen.findByText("EV_IPL")).toBeTruthy();

    tpm.getEventLog.mockResolvedValue({ data: { entries: [entry(9, "EV_IPL_NEW")] } });
    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));

    expect(await screen.findByText("EV_IPL_NEW")).toBeTruthy();
    await waitFor(() => expect(tpm.getEventLog).toHaveBeenCalledTimes(2));
  });
});
