import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { SERVICE_NOT_CONFIGURED } from "trusted-platform-sdk";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import SnapshotsPage from "./page";

// #1827: unit tests for the snapshots page. It lists every VM, gathers each
// VM's snapshots, totals their size, and restores or deletes one after a
// confirm.

const service = {
  listVMs: vi.fn(),
  listSnapshots: vi.fn(),
  deleteSnapshot: vi.fn(),
  restoreSnapshot: vi.fn(),
};
const toast = vi.fn();
const confirmMock = vi.fn();

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useCompute: () => service,
  useToast: () => ({ toast }),
}));

vi.mock("@/components/features/platform", () => ({
  ServiceUnavailableState: ({ service: name }: { service: string }) => (
    <div data-testid="service-unavailable">{name}</div>
  ),
}));

// Plain elements stand in for the Radix menu, which jsdom cannot open.
vi.mock("@/components/ui/dropdown-menu", () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <span>{children}</span>,
  DropdownMenuSeparator: () => null,
  DropdownMenuItem: ({ children, onClick }: { children: ReactNode; onClick?: () => void }) => (
    <button onClick={onClick}>{children}</button>
  ),
}));

const MiB = 1024 * 1024;

const vms = {
  success: true,
  data: {
    vms: [
      { id: "vm-1", config: { name: "web" } },
      { id: "vm-2" },
    ],
  },
};

function snapshotsFor(vmId: string) {
  if (vmId === "vm-1") {
    return Promise.resolve({
      success: true,
      data: {
        snapshots: [
          {
            id: "s-1",
            vmId: "vm-1",
            config: { name: "before-upgrade", description: "pre 2.0" },
            sizeBytes: 512 * MiB,
            vmState: "VM_STATE_RUNNING",
            createdAt: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
          },
        ],
      },
    });
  }
  return Promise.resolve({
    success: true,
    data: { snapshots: [{ id: "s-2", vmId: "vm-2", sizeBytes: 1536 * MiB }] },
  });
}

function card(label: string): string | null {
  return screen.getByText(label).nextElementSibling?.textContent ?? null;
}

async function tableRows(): Promise<HTMLElement[]> {
  await screen.findByRole("table");
  return screen.getAllByRole("row").slice(1);
}

describe("SnapshotsPage", () => {
  beforeEach(() => {
    vi.stubGlobal("confirm", confirmMock);
    service.listVMs.mockResolvedValue(vms);
    service.listSnapshots.mockImplementation(snapshotsFor);
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
    vi.unstubAllGlobals();
  });

  it("gathers every VM's snapshots with source, state, size and age", async () => {
    render(<SnapshotsPage />);
    const [first, second] = await tableRows();

    expect(service.listSnapshots).toHaveBeenCalledWith("vm-1");
    expect(service.listSnapshots).toHaveBeenCalledWith("vm-2");
    const firstCells = within(first).getAllByRole("cell").map((c) => c.textContent);
    expect(firstCells.slice(0, 6)).toEqual([
      "before-upgradepre 2.0",
      "web",
      "VM",
      "RUNNING",
      "512 MB",
      "about 2 hours ago",
    ]);
    // A VM and a snapshot without a name fall back to their ids.
    const secondCells = within(second).getAllByRole("cell").map((c) => c.textContent);
    expect(secondCells.slice(0, 6)).toEqual(["s-2", "vm-2", "VM", "UNKNOWN", "1.5 GB", "Unknown"]);

    expect(card("Total Snapshots")).toBe("2");
    expect(card("VM Snapshots")).toBe("2");
    expect(card("Total Size")).toBe("2.0 GB");
  });

  it("says to create a VM first when there are none", async () => {
    service.listVMs.mockResolvedValue({ success: true, data: { vms: [] } });
    render(<SnapshotsPage />);

    expect(await screen.findByText(/Create a VM first to take snapshots/)).toBeTruthy();
    expect(service.listSnapshots).not.toHaveBeenCalled();
    expect(card("Total Size")).toBe("0 MB");
  });

  it("says no snapshots exist when the VMs have none", async () => {
    service.listSnapshots.mockResolvedValue({ success: true, data: {} });
    render(<SnapshotsPage />);

    expect(await screen.findByText(/No snapshots have been created yet/)).toBeTruthy();
    expect(card("Total Snapshots")).toBe("0");
  });

  it("shows the compute-not-configured state on a structured 503 without a toast", async () => {
    service.listVMs.mockResolvedValue({
      success: false,
      error: { status: 503, message: "not configured", details: { reason: SERVICE_NOT_CONFIGURED } },
    });
    render(<SnapshotsPage />);

    expect((await screen.findByTestId("service-unavailable")).textContent).toBe("Compute");
    expect(toast).not.toHaveBeenCalled();
  });

  it("shows the VM list error with a retry that refetches", async () => {
    service.listVMs.mockResolvedValue({ success: false, error: { status: 500, message: "vm list broke" } });
    render(<SnapshotsPage />);

    expect(await screen.findByText("Error Loading Snapshots")).toBeTruthy();
    expect(screen.getByText("vm list broke")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Error loading VMs", variant: "destructive" })
    );

    service.listVMs.mockResolvedValue(vms);
    fireEvent.click(screen.getByText("Retry"));
    expect(await tableRows()).toHaveLength(2);
  });

  it("shows a snapshot list failure as an error", async () => {
    service.listSnapshots.mockRejectedValue(new Error("snapshots broke"));
    render(<SnapshotsPage />);

    expect(await screen.findByText("snapshots broke")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Error loading snapshots", description: "snapshots broke" })
    );
  });

  it("restores a snapshot after confirm and reloads the VMs", async () => {
    confirmMock.mockReturnValue(true);
    service.restoreSnapshot.mockResolvedValue({ success: true, data: {} });
    render(<SnapshotsPage />);
    const [first] = await tableRows();

    fireEvent.click(within(first).getByText("Restore"));
    expect(confirmMock).toHaveBeenCalledWith("Are you sure you want to restore from snapshot before-upgrade?");
    await vi.waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Restore initiated" }))
    );
    expect(service.restoreSnapshot).toHaveBeenCalledWith({ vmId: "vm-1", snapshotId: "s-1" });
    await vi.waitFor(() => expect(service.listVMs).toHaveBeenCalledTimes(2));
  });

  it("toasts a failed restore", async () => {
    confirmMock.mockReturnValue(true);
    service.restoreSnapshot.mockRejectedValue(new Error("vm busy"));
    render(<SnapshotsPage />);
    const [first] = await tableRows();

    fireEvent.click(within(first).getByText("Restore"));
    await vi.waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error restoring snapshot", description: "vm busy" })
      )
    );
  });

  it("deletes a snapshot after confirm and reloads the snapshots", async () => {
    confirmMock.mockReturnValue(true);
    service.deleteSnapshot.mockResolvedValue({ success: true, data: {} });
    render(<SnapshotsPage />);
    const [, second] = await tableRows();
    const calls = service.listSnapshots.mock.calls.length;

    fireEvent.click(within(second).getByText("Delete"));
    expect(confirmMock).toHaveBeenCalledWith("Are you sure you want to delete snapshot s-2?");
    await vi.waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Snapshot deleted" }))
    );
    expect(service.deleteSnapshot).toHaveBeenCalledWith({ vmId: "vm-2", snapshotId: "s-2" });
    await vi.waitFor(() => expect(service.listSnapshots.mock.calls.length).toBeGreaterThan(calls));
  });

  it("toasts a failed delete", async () => {
    confirmMock.mockReturnValue(true);
    service.deleteSnapshot.mockRejectedValue(new Error("in use"));
    render(<SnapshotsPage />);
    const [first] = await tableRows();

    fireEvent.click(within(first).getByText("Delete"));
    await vi.waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error deleting snapshot", description: "in use" })
      )
    );
  });

  it("neither restores nor deletes when the confirm is declined", async () => {
    confirmMock.mockReturnValue(false);
    render(<SnapshotsPage />);
    const [first] = await tableRows();

    fireEvent.click(within(first).getByText("Restore"));
    fireEvent.click(within(first).getByText("Delete"));
    expect(confirmMock).toHaveBeenCalledTimes(2);
    expect(service.restoreSnapshot).not.toHaveBeenCalled();
    expect(service.deleteSnapshot).not.toHaveBeenCalled();
  });

  it("says clone, export and create are not available yet", async () => {
    render(<SnapshotsPage />);
    const [first] = await tableRows();

    fireEvent.click(within(first).getByText("Clone to New Instance"));
    fireEvent.click(within(first).getByText("Export"));
    fireEvent.click(screen.getByText("Create Snapshot"));
    const descriptions = toast.mock.calls.map((c) => (c[0] as { description: string }).description);
    expect(descriptions).toEqual([
      "Snapshot cloning is not yet implemented in the API",
      "Snapshot export is not yet implemented in the API",
      "Create snapshot from this page coming soon. Use VM details page to create snapshots.",
    ]);
  });
});
