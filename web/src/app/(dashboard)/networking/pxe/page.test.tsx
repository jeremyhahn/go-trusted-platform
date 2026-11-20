import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #1845: the page reads PXE devices and status through the PXE client and,
// where PXE is not served, the gateways' reports. These tests stub those
// clients (the network boundary) and the toast hook.

const toast = vi.fn();
const pxe = {
  listDevices: vi.fn(),
  getStatus: vi.fn(),
  registerDevice: vi.fn(),
};
const reported = vi.fn();

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  usePXE: () => pxe,
  useToast: () => ({ toast }),
  useReportedGateways: (opts: { enabled: boolean }) => reported(opts),
  usePXEDevice: () => deviceCtl,
  usePXEServiceControl: () => serviceCtl,
}));

type DeviceCtl = {
  device: Record<string, unknown> | null;
  events: Record<string, unknown>[];
  busy: boolean;
  error: string | null;
  notice: string | null;
  [fn: string]: unknown;
};

const deviceFns = [
  "open",
  "lookupByMAC",
  "close",
  "updateState",
  "setEnrolled",
  "authorize",
  "quarantine",
  "retry",
  "remove",
] as const;

const deviceCtl: DeviceCtl = { device: null, events: [], busy: false, error: null, notice: null };
const serviceCtl = {
  busy: false,
  error: null as string | null,
  notice: null as string | null,
  start: vi.fn(),
  stop: vi.fn(),
};

function resetCtls() {
  Object.assign(deviceCtl, { device: null, events: [], busy: false, error: null, notice: null });
  for (const fn of deviceFns) deviceCtl[fn] = vi.fn().mockResolvedValue(undefined);
  Object.assign(serviceCtl, { busy: false, error: null, notice: null });
  serviceCtl.start = vi.fn().mockResolvedValue(undefined);
  serviceCtl.stop = vi.fn().mockResolvedValue(undefined);
}
resetCtls();

import PXEBootPage from "./page";

const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();

const authorized = {
  id: "d1",
  macAddress: "aa:bb:cc:00:00:01",
  state: "AUTHORIZED",
  currentVlan: 20,
  targetVlan: 30,
  certificateSerial: "0123456789abcdef0123",
  createdAt: minutesAgo(5),
  updatedAt: minutesAgo(5),
};
const booting = { id: "d2", macAddress: "aa:bb:cc:00:00:02", state: "BOOTING" };
const quarantined = { id: "d3", macAddress: "aa:bb:cc:00:00:03", state: "QUARANTINED" };
const failed = { id: "d4", macAddress: "aa:bb:cc:00:00:04", state: "FAILED" };
const enrolled = { id: "d5", macAddress: "aa:bb:cc:00:00:05", state: "ENROLLED" };
const installing = { id: "d6", macAddress: "aa:bb:cc:00:00:06", state: "INSTALLING" };

const notConfigured = Object.assign(new Error("pxe service not configured"), {
  status: 503,
  details: { reason: "SERVICE_NOT_CONFIGURED" },
});

/** The figure under a stat card's title. */
function stat(title: string) {
  return screen.getByText(title).nextElementSibling?.textContent;
}

describe("PXEBootPage", () => {
  beforeEach(() => {
    resetCtls();
    toast.mockReset();
    reported.mockReset();
    reported.mockReturnValue({ gateways: [], isLoading: false });
    for (const fn of Object.values(pxe)) fn.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("lists the devices, their counts by state and the service status", async () => {
    pxe.listDevices.mockResolvedValue({
      data: { devices: [authorized, booting, quarantined, failed, enrolled, installing] },
    });
    pxe.getStatus.mockResolvedValue({
      data: { status: { running: true, deviceCount: 6, quarantineVlan: 99, provisioningVlan: 10 } },
    });

    render(<PXEBootPage />);

    expect(await screen.findByText("Running")).toBeTruthy();
    expect(reported).toHaveBeenLastCalledWith({ enabled: false });
    expect(stat("Total Devices")).toBe("6");
    expect(stat("Authorized")).toBe("1");
    expect(stat("Enrolled")).toBe("1");
    expect(stat("Provisioning")).toBe("2");
    expect(stat("Failed")).toBe("2");
    expect(screen.getByText("VLAN 99")).toBeTruthy();
    expect(screen.getByText("VLAN 10")).toBeTruthy();
    expect(screen.getByText("VLAN 20")).toBeTruthy();
    expect(screen.getByText("VLAN 30")).toBeTruthy();
    expect(screen.getByText("0123456789abcdef...")).toBeTruthy();
    expect(screen.getAllByText("5 minutes ago").length).toBe(3);
    // The recent list shows five devices, the full list all six.
    expect(screen.getAllByText("aa:bb:cc:00:00:01")).toHaveLength(2);
    expect(screen.getAllByText("aa:bb:cc:00:00:06")).toHaveLength(1);
  });

  it("shows a stopped service, no status and no devices", async () => {
    pxe.listDevices.mockResolvedValue({ data: { devices: [] } });
    pxe.getStatus.mockResolvedValue({ data: { status: { running: false } } });

    render(<PXEBootPage />);

    expect(await screen.findByText("Stopped")).toBeTruthy();
    expect(screen.queryByText("Device Count")).toBeNull();
    expect(screen.queryByText("Quarantine VLAN")).toBeNull();
    expect(screen.getAllByText("No devices found")).toHaveLength(2);
  });

  it("says the status is not available when the status is empty", async () => {
    pxe.listDevices.mockResolvedValue({ data: { devices: [{ id: "d9", macAddress: "aa:bb:cc:00:00:09" }] } });
    pxe.getStatus.mockResolvedValue({ data: {} });

    render(<PXEBootPage />);

    expect(await screen.findByText("PXE service status not available")).toBeTruthy();
    expect(stat("Total Devices")).toBe("1");
    expect(screen.getAllByText("-").length).toBeGreaterThanOrEqual(5);
  });

  it("shows the gateways that serve PXE when this node does not", async () => {
    pxe.listDevices.mockRejectedValue(notConfigured);
    pxe.getStatus.mockRejectedValue(notConfigured);
    reported.mockReturnValue({
      gateways: [
        {
          gateway_id: "gw-1",
          hostname: "edge-1",
          reported_at: minutesAgo(1),
          pxe: { status: "running", listen_address: ":67", boots_served: 4 },
        },
        { gateway_id: "gw-2", reported_at: minutesAgo(1) },
      ],
      isLoading: false,
    });

    render(<PXEBootPage />);

    expect(await screen.findByText("edge-1")).toBeTruthy();
    expect(reported).toHaveBeenLastCalledWith({ enabled: true });
    expect(screen.getByText("running")).toBeTruthy();
    expect(screen.getByText(":67")).toBeTruthy();
    expect(screen.getByText("4")).toBeTruthy();
    // A gateway without a hostname or a PXE section.
    expect(screen.getByText("gw-2")).toBeTruthy();
    expect(screen.getByText("unknown")).toBeTruthy();
    expect(screen.getByText("—")).toBeTruthy();
    expect(screen.queryByText("Error Loading PXE Boot")).toBeNull();
    expect(toast).not.toHaveBeenCalled();
  });

  it("says when no gateway has reported, and while the reports load", async () => {
    pxe.listDevices.mockResolvedValue({ data: { devices: [] } });
    pxe.getStatus.mockRejectedValue(notConfigured);

    render(<PXEBootPage />);

    expect(await screen.findByText("No gatewayd processes have reported yet.")).toBeTruthy();

    cleanup();
    reported.mockReturnValue({ gateways: [], isLoading: true });
    render(<PXEBootPage />);
    expect(await screen.findByText("Loading reported gateways…")).toBeTruthy();
  });

  it("shows the error state for any other failure, and retries both reads", async () => {
    pxe.listDevices.mockRejectedValueOnce(new Error("pxe: database locked"));
    pxe.listDevices.mockResolvedValue({ data: { devices: [authorized] } });
    pxe.getStatus.mockResolvedValue({ data: { status: { running: true } } });

    render(<PXEBootPage />);

    expect(await screen.findByText("Error Loading PXE Boot")).toBeTruthy();
    expect(screen.getByText("pxe: database locked")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Error loading devices", variant: "destructive" })
    );

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByText("Running")).toBeTruthy();
    expect(pxe.getStatus).toHaveBeenCalledTimes(2);
  });

  it("toasts a failed status read", async () => {
    pxe.listDevices.mockResolvedValue({ data: { devices: [] } });
    pxe.getStatus.mockRejectedValue(new Error("status timeout"));

    render(<PXEBootPage />);

    expect(await screen.findByText("status timeout")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error loading PXE status" }));
  });

  it("registers a device by MAC address and reloads the devices", async () => {
    pxe.listDevices.mockResolvedValue({ data: { devices: [] } });
    pxe.getStatus.mockResolvedValue({ data: { status: { running: true } } });
    pxe.registerDevice.mockResolvedValue({ data: {} });

    render(<PXEBootPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Register Device" }));

    const register = screen.getByRole("button", { name: "Register" }) as HTMLButtonElement;
    expect(register.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("MAC Address *"), { target: { value: "aa:bb:cc:11:22:33" } });
    fireEvent.click(register);

    await waitFor(() => expect(screen.queryByLabelText("MAC Address *")).toBeNull());
    expect(pxe.registerDevice).toHaveBeenCalledWith({ macAddress: "aa:bb:cc:11:22:33" });
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Device registered" }));
    await waitFor(() => expect(pxe.listDevices).toHaveBeenCalledTimes(2));
  });

  it("keeps the register dialog open when the device is refused", async () => {
    pxe.listDevices.mockResolvedValue({ data: { devices: [] } });
    pxe.getStatus.mockResolvedValue({ data: { status: { running: true } } });
    pxe.registerDevice.mockRejectedValue(new Error("invalid MAC address"));

    render(<PXEBootPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Register Device" }));
    fireEvent.change(screen.getByLabelText("MAC Address *"), { target: { value: "zz" } });
    fireEvent.click(screen.getByRole("button", { name: "Register" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Failed to register device", description: "invalid MAC address" })
      )
    );
    expect((screen.getByLabelText("MAC Address *") as HTMLInputElement).value).toBe("zz");
    expect((screen.getByRole("button", { name: "Register" }) as HTMLButtonElement).disabled).toBe(false);
  });
});

describe("PXEBootPage device operations (#2062)", () => {
  beforeEach(() => {
    resetCtls();
    reported.mockReturnValue({ gateways: [], isLoading: false });
    pxe.listDevices.mockResolvedValue({ data: { devices: [booting] } });
    pxe.getStatus.mockResolvedValue({ data: { status: { running: true, deviceCount: 1 } } });
  });

  afterEach(() => {
    cleanup();
  });

  it("looks a device up by MAC and opens a listed device by ID", async () => {
    render(<PXEBootPage />);
    await screen.findByText("All Devices");

    fireEvent.change(screen.getByLabelText("Device MAC address"), { target: { value: "aa:bb:cc:00:00:02" } });
    fireEvent.click(screen.getByRole("button", { name: "Look up" }));
    expect(deviceCtl.lookupByMAC).toHaveBeenCalledWith("aa:bb:cc:00:00:02");

    fireEvent.click(screen.getByRole("button", { name: "Manage aa:bb:cc:00:00:02" }));
    expect(deviceCtl.open).toHaveBeenCalledWith("d2");
  });

  it("shows the open device, its events, and drives each operation", async () => {
    deviceCtl.device = { id: "d3", macAddress: "aa:bb:cc:00:00:03", state: "QUARANTINED" };
    deviceCtl.events = [
      { id: "e1", deviceId: "d3", timestamp: minutesAgo(1), eventType: "QUARANTINED", toState: "QUARANTINED" },
    ];
    render(<PXEBootPage />);
    const detail = await screen.findByTestId("pxe-device-detail");
    expect(screen.getByTestId("pxe-device-state").textContent).toBe("QUARANTINED");
    expect(screen.getByTestId("pxe-device-events").querySelectorAll("li")).toHaveLength(1);
    expect(detail.textContent).toContain("d3");

    fireEvent.change(screen.getByLabelText("Quarantine reason"), { target: { value: "bad quote" } });
    fireEvent.click(screen.getByRole("button", { name: "Quarantine" }));
    expect(deviceCtl.quarantine).toHaveBeenCalledWith("bad quote");

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(deviceCtl.retry).toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText("New state"), { target: { value: "ENROLLED" } });
    fireEvent.change(screen.getByLabelText("State reason"), { target: { value: "manual" } });
    fireEvent.click(screen.getByRole("button", { name: "Set state" }));
    expect(deviceCtl.updateState).toHaveBeenCalledWith("ENROLLED", "manual");

    fireEvent.change(screen.getByLabelText("Certificate serial"), { target: { value: "0a1b" } });
    fireEvent.click(screen.getByRole("button", { name: "Mark enrolled" }));
    expect(deviceCtl.setEnrolled).toHaveBeenCalledWith("0a1b");

    fireEvent.change(screen.getByLabelText("Target VLAN"), { target: { value: "200" } });
    fireEvent.click(screen.getByRole("button", { name: "Authorize" }));
    expect(deviceCtl.authorize).toHaveBeenCalledWith(200);

    fireEvent.click(screen.getByRole("button", { name: "Remove device" }));
    expect(deviceCtl.remove).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Confirm remove" }));
    expect(deviceCtl.remove).toHaveBeenCalled();
    await waitFor(() => expect(pxe.listDevices.mock.calls.length).toBeGreaterThan(1));
  });

  it("shows the operation error", async () => {
    deviceCtl.error = "device not found";
    render(<PXEBootPage />);
    expect((await screen.findByRole("alert")).textContent).toBe("device not found");
  });

  it("stops a running service and starts a stopped one", async () => {
    const { unmount } = render(<PXEBootPage />);
    await screen.findByText("Running");
    expect(screen.getByRole("button", { name: "Start service" })).toHaveProperty("disabled", true);
    fireEvent.click(screen.getByRole("button", { name: "Stop service" }));
    expect(serviceCtl.stop).toHaveBeenCalled();
    unmount();

    pxe.getStatus.mockResolvedValue({ data: { status: { running: false, deviceCount: 1 } } });
    render(<PXEBootPage />);
    await screen.findByText("Stopped");
    fireEvent.click(screen.getByRole("button", { name: "Start service" }));
    expect(serviceCtl.start).toHaveBeenCalled();
  });

  it("gates the install-complete webhook off with its reason", async () => {
    render(<PXEBootPage />);
    const control = await screen.findByRole("button", { name: "Send install-complete webhook" });
    expect(control).toHaveProperty("disabled", true);
    expect(screen.getByTestId("pxe-webhook-gate-reason").textContent).toContain("machine-facing");
  });
});
