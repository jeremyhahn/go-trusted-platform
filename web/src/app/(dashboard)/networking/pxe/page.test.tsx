import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2062: each All Devices row authorizes (target VLAN), quarantines
// (reason), retries and removes the device through client.pxe (network
// boundary, mocked here).

const { pxe, toast, off } = vi.hoisted(() => ({
  pxe: {
    listDevices: vi.fn(),
    getStatus: vi.fn(),
    registerDevice: vi.fn(),
    authorizeDevice: vi.fn(),
    quarantineDevice: vi.fn(),
    retryDevice: vi.fn(),
    removeDevice: vi.fn(),
  },
  toast: vi.fn(),
  off: new Set<string>(),
}));

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: "not-configured: pxe" } : { enabled: true },
  }),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  usePXE: () => pxe,
  useReportedGateways: () => ({ gateways: [], isLoading: false }),
}));

vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  usePXE: () => pxe,
}));

vi.mock("@/hooks/use-toast", () => ({ useToast: () => ({ toast }) }));

import PXEBootPage from "./page";

const MAC = "00:11:22:33:44:55";

beforeEach(() => {
  vi.clearAllMocks();
  off.clear();
  pxe.listDevices.mockResolvedValue({
    data: { devices: [{ id: "dev-1", macAddress: MAC, state: "FAILED", targetVlan: 100 }] },
  });
  pxe.getStatus.mockResolvedValue({ data: { status: { running: true } } });
  pxe.authorizeDevice.mockResolvedValue({ data: {} });
  pxe.quarantineDevice.mockResolvedValue({ data: {} });
  pxe.retryDevice.mockResolvedValue({ data: {} });
  pxe.removeDevice.mockResolvedValue({ data: {} });
});

afterEach(() => cleanup());

describe("PXE page device actions", () => {
  it("authorizes with the target VLAN preset from the device and refreshes", async () => {
    render(<PXEBootPage />);
    fireEvent.click(await screen.findByRole("button", { name: `Authorize ${MAC}` }));
    const dialog = within(await screen.findByRole("dialog"));
    expect((dialog.getByLabelText(/Target VLAN/) as HTMLInputElement).value).toBe("100");
    const calls = pxe.listDevices.mock.calls.length;
    fireEvent.click(dialog.getByRole("button", { name: "Authorize" }));
    await waitFor(() =>
      expect(pxe.authorizeDevice).toHaveBeenCalledWith({ deviceId: "dev-1", targetVlan: 100 }),
    );
    await waitFor(() => expect(pxe.listDevices.mock.calls.length).toBeGreaterThan(calls));
  });

  it("quarantines only once a reason is typed", async () => {
    render(<PXEBootPage />);
    fireEvent.click(await screen.findByRole("button", { name: `Quarantine ${MAC}` }));
    const dialog = within(await screen.findByRole("dialog"));
    const confirm = dialog.getByRole("button", { name: "Quarantine" }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.change(dialog.getByLabelText(/Reason/), { target: { value: "tamper" } });
    expect(confirm.disabled).toBe(false);
    fireEvent.click(confirm);
    await waitFor(() =>
      expect(pxe.quarantineDevice).toHaveBeenCalledWith({ deviceId: "dev-1", reason: "tamper" }),
    );
  });

  it("retries at once with no dialog", async () => {
    render(<PXEBootPage />);
    fireEvent.click(await screen.findByRole("button", { name: `Retry ${MAC}` }));
    await waitFor(() => expect(pxe.retryDevice).toHaveBeenCalledWith("dev-1"));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("removes after confirmation", async () => {
    render(<PXEBootPage />);
    fireEvent.click(await screen.findByRole("button", { name: `Remove ${MAC}` }));
    const dialog = within(await screen.findByRole("dialog"));
    fireEvent.click(dialog.getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(pxe.removeDevice).toHaveBeenCalledWith("dev-1"));
  });

  it("withholds the device actions the server does not offer", async () => {
    for (const op of [
      "POST /api/v1/pxe/devices/{id}/authorize",
      "POST /api/v1/pxe/devices/{id}/quarantine",
      "POST /api/v1/pxe/devices/{id}/retry",
      "DELETE /api/v1/pxe/devices/{id}",
      "POST /api/v1/pxe/devices",
    ]) {
      off.add(op);
    }
    render(<PXEBootPage />);
    await screen.findByRole("button", { name: `Authorize ${MAC}` });
    for (const name of [
      `Authorize ${MAC}`,
      `Quarantine ${MAC}`,
      `Retry ${MAC}`,
      `Remove ${MAC}`,
      "Register Device",
    ]) {
      const button = screen.getByRole("button", { name }) as HTMLButtonElement;
      expect(button.disabled).toBe(true);
      expect(button.getAttribute("data-capability-enabled")).toBe("false");
      expect(button.getAttribute("title")).toBe("not-configured: pxe");
    }
  });
});
