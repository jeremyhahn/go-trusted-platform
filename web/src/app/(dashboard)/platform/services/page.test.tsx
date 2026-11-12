import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ServicesPage from "./page";

// One stable platform client: the daemon hook's useApi calls key on it, and a
// fresh object per render would refetch on every pass.
const ok = <T,>(data: T) => Promise.resolve({ success: true, data });
const platform = {
  getHealth: vi.fn(() => ok({ health: { healthy: true, services: [], timestamp: "t" } })),
  getStatus: vi.fn(() => ok({ status: "running", version: "1.2.3", timestamp: "t" })),
  getVersion: vi.fn(() => ok({ version: { version: "1.2.3", gitCommit: "abc1234" } })),
  getConfig: vi.fn(() => ok({ config: { logLevel: "info", configFile: "platform.yaml" } })),
  reloadConfig: vi.fn(() => ok({ status: { success: true, message: "Configuration reloaded" } })),
  listServices: vi.fn(() =>
    ok({
      services: [
        { name: "dns", status: "running" },
        { name: "pxe", status: "stopped" },
      ],
      count: 2,
    })
  ),
  getServiceStatus: vi.fn(() => ok({ name: "dns", status: "running", uptime: "5m" })),
  startService: vi.fn(() => ok({ service: "dns", action: "start", success: true, message: "start ok" })),
  stopService: vi.fn(() => ok({ service: "dns", action: "stop", success: true, message: "stop ok" })),
  restartService: vi.fn(() =>
    ok({ service: "dns", action: "restart", success: true, message: "restart ok" })
  ),
};
const toastResult = { toast: vi.fn() };

// The real useApi drives the real daemon hook; only the client is mocked.
vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  usePlatform: () => platform,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useToast: () => toastResult,
}));

// The Radix dialog portal does not settle in jsdom: render the parts inline,
// and the content only while the page holds the dialog open.
vi.mock("@/components/ui/dialog", () => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Dialog = ({ open, children }: { open?: boolean; children?: React.ReactNode }) =>
    open ? <div role="dialog">{children}</div> : null;
  const DialogTitle = ({ children }: { children?: React.ReactNode }) => <h2>{children}</h2>;
  return {
    Dialog,
    DialogContent: Pass,
    DialogHeader: Pass,
    DialogFooter: Pass,
    DialogDescription: Pass,
    DialogTitle,
  };
});

async function renderPage() {
  render(<ServicesPage />);
  await screen.findByLabelText("Stop dns");
}

describe("ServicesPage daemon controls", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  afterEach(() => {
    cleanup();
  });

  it("stop calls stopService only after the confirm button", async () => {
    await renderPage();
    fireEvent.click(screen.getByLabelText("Stop dns"));
    expect(screen.getByRole("dialog")).toBeTruthy();
    expect(screen.getByText("Stop dns?")).toBeTruthy();
    expect(platform.stopService).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(platform.stopService).toHaveBeenCalledTimes(1));
    expect(platform.stopService).toHaveBeenCalledWith("dns");
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("cancel closes the stop dialog without calling stopService", async () => {
    await renderPage();
    fireEvent.click(screen.getByLabelText("Stop dns"));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(platform.stopService).not.toHaveBeenCalled();
  });

  it("restart asks for confirmation first", async () => {
    await renderPage();
    fireEvent.click(screen.getByLabelText("Restart dns"));
    expect(screen.getByText("Restart dns?")).toBeTruthy();
    expect(platform.restartService).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(platform.restartService).toHaveBeenCalledWith("dns"));
  });

  it("start calls startService without a dialog", async () => {
    await renderPage();
    fireEvent.click(screen.getByLabelText("Start pxe"));
    expect(screen.queryByRole("dialog")).toBeNull();
    await waitFor(() => expect(platform.startService).toHaveBeenCalledWith("pxe"));
  });

  it("reload configuration calls reloadConfig", async () => {
    await renderPage();
    fireEvent.click(screen.getByRole("button", { name: /Reload Config/ }));
    await waitFor(() => expect(platform.reloadConfig).toHaveBeenCalledTimes(1));
  });

  it("shows daemon status and version", async () => {
    await renderPage();
    await waitFor(() => expect(screen.getByTestId("daemon-status").textContent).toContain("running"));
    await waitFor(() => expect(screen.getByTestId("daemon-version").textContent).toContain("1.2.3"));
  });
});
