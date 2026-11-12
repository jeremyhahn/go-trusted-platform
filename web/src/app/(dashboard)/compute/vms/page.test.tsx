import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { SERVICE_NOT_CONFIGURED } from "trusted-platform-sdk";
import { afterEach, describe, expect, it, vi } from "vitest";

import VMsPage from "./page";

// #1827: unit tests for the VMs dashboard page. The page reads the SDK's VMs
// into the console's VM type, counts them by status, filters them, and shows
// an informational state when compute is not wired on this node.

const service = {
  listVMs: vi.fn(),
};
const toast = vi.fn();

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useCompute: () => service,
  useToast: () => ({ toast }),
}));

type Row = {
  id: string;
  name: string;
  status: string;
  vcpus: number;
  memoryMB: number;
  storageMB: number;
  ipAddress?: string;
  createdAt: string;
};

vi.mock("@/components/features/compute/vm-table", () => ({
  VMTable: ({ vms, onRefresh }: { vms: Row[]; onRefresh: () => void }) => (
    <div>
      <ul data-testid="vm-rows">
        {vms.map((v) => (
          <li key={v.id}>
            {`${v.id}|${v.name}|${v.status}|${v.vcpus}|${v.memoryMB}|${v.storageMB}|${v.ipAddress ?? "-"}|${v.createdAt}`}
          </li>
        ))}
      </ul>
      <button onClick={onRefresh}>table-refresh</button>
    </div>
  ),
}));

vi.mock("@/components/features/compute/vm-form", () => ({
  VMForm: ({ open, onSuccess }: { open: boolean; onSuccess: () => void }) => (
    <div data-testid="vm-form" data-open={String(open)}>
      <button onClick={onSuccess}>form-success</button>
    </div>
  ),
}));

vi.mock("@/components/features/platform", () => ({
  ServiceUnavailableState: ({ service: name, description }: { service: string; description: string }) => (
    <div data-testid="service-unavailable">{`${name}: ${description}`}</div>
  ),
}));

// A native select stands in for the Radix one, which jsdom cannot open.
vi.mock("@/components/ui/select", () => ({
  Select: ({ value, onValueChange, children }: { value: string; onValueChange: (v: string) => void; children: ReactNode }) => (
    <select aria-label="status-filter" value={value} onChange={(e) => onValueChange(e.target.value)}>
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  SelectItem: ({ value, children }: { value: string; children: ReactNode }) => <option value={value}>{children}</option>,
}));

function ok(vms: unknown[]) {
  return { data: { vms }, success: true };
}

const sample = [
  {
    id: "vm-1",
    state: "VM_STATE_RUNNING",
    createdAt: "2026-11-01T00:00:00Z",
    config: { name: "web", cpu: { cores: 4 }, memory: { sizeMb: 8192 }, disks: [{ sizeGb: 20 }, { sizeGb: 100 }] },
  },
  { id: "vm-2", state: "VM_STATE_STOPPED", createdAt: "2026-11-02T00:00:00Z", config: { name: "db" } },
  { id: "vm-3", state: "VM_STATE_SUSPENDED", createdAt: "2026-11-03T00:00:00Z", config: { disks: [] } },
  { id: "vm-4", createdAt: "2026-11-04T00:00:00Z" },
];

function stat(label: string): string | null {
  // The filter's options carry the same labels; the counter is a div.
  const card = screen.getAllByText(label).find((el) => el.tagName === "DIV");
  return card?.nextElementSibling?.textContent ?? null;
}

async function rows(): Promise<string[]> {
  const list = await screen.findByTestId("vm-rows");
  return Array.from(list.querySelectorAll("li")).map((li) => li.textContent ?? "");
}

describe("VMsPage", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("maps SDK VMs into rows: first disk in MB, zero defaults, no IP", async () => {
    service.listVMs.mockResolvedValue(ok(sample));
    render(<VMsPage />);

    expect(await rows()).toEqual([
      "vm-1|web|running|4|8192|20480|-|2026-11-01T00:00:00Z",
      "vm-2|db|stopped|0|0|0|-|2026-11-02T00:00:00Z",
      "vm-3|vm-3|suspended|0|0|0|-|2026-11-03T00:00:00Z",
      "vm-4|vm-4|creating|0|0|0|-|2026-11-04T00:00:00Z",
    ]);
    expect(stat("Total VMs")).toBe("4");
    expect(stat("Running")).toBe("1");
    expect(stat("Stopped")).toBe("1");
    expect(stat("Suspended")).toBe("1");
    expect(toast).not.toHaveBeenCalled();
  });

  it("stamps a VM without a creation time with the current time", async () => {
    service.listVMs.mockResolvedValue(ok([{ id: "vm-9", state: "VM_STATE_RUNNING" }]));
    render(<VMsPage />);

    const [row] = await rows();
    expect(Number.isNaN(Date.parse(row.split("|")[7]))).toBe(false);
  });

  it("filters the rows by status and back to all", async () => {
    service.listVMs.mockResolvedValue(ok(sample));
    render(<VMsPage />);
    await rows();

    const filter = screen.getByLabelText("status-filter");
    fireEvent.change(filter, { target: { value: "suspended" } });
    expect((await rows()).map((r) => r.split("|")[0])).toEqual(["vm-3"]);

    fireEvent.change(filter, { target: { value: "creating" } });
    expect((await rows()).map((r) => r.split("|")[0])).toEqual(["vm-4"]);

    fireEvent.change(filter, { target: { value: "all" } });
    expect(await rows()).toHaveLength(4);
    // The counters do not follow the filter.
    expect(stat("Total VMs")).toBe("4");
  });

  it("shows zero counters and no rows for a missing list", async () => {
    service.listVMs.mockResolvedValue({ data: {}, success: true });
    render(<VMsPage />);

    expect(await rows()).toEqual([]);
    expect(stat("Total VMs")).toBe("0");
    expect(stat("Suspended")).toBe("0");
  });

  it("toasts a fetch error and still renders the empty page", async () => {
    service.listVMs.mockResolvedValue({ error: { status: 500, message: "boom" }, success: false });
    render(<VMsPage />);

    await vi.waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive", description: "Failed to fetch VMs: boom" })
      )
    );
    expect(await rows()).toEqual([]);
    expect(screen.queryByTestId("service-unavailable")).toBeNull();
  });

  it("treats a 503 without the not-configured reason as a real error", async () => {
    service.listVMs.mockResolvedValue({ error: { status: 503, message: "upstream down" }, success: false });
    render(<VMsPage />);

    await vi.waitFor(() => expect(toast).toHaveBeenCalled());
    expect(screen.queryByTestId("service-unavailable")).toBeNull();
    expect(screen.getByText("Create VM")).toBeTruthy();
  });

  it("toasts when the client throws instead of returning an error", async () => {
    service.listVMs.mockRejectedValue(new Error("network"));
    render(<VMsPage />);

    await vi.waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "Failed to fetch VMs: network" }))
    );
  });

  it("shows the compute-not-configured state on a structured 503 without a toast", async () => {
    service.listVMs.mockResolvedValue({
      error: { status: 503, message: "compute is not configured", details: { reason: SERVICE_NOT_CONFIGURED } },
      success: false,
    });
    render(<VMsPage />);

    const state = await screen.findByTestId("service-unavailable");
    expect(state.textContent).toContain("Compute:");
    expect(screen.queryByText("Create VM")).toBeNull();
    expect(screen.queryByTestId("vm-rows")).toBeNull();
    expect(toast).not.toHaveBeenCalled();
  });

  it("refetches from the table and the form", async () => {
    service.listVMs.mockResolvedValue(ok(sample));
    render(<VMsPage />);
    await rows();
    expect(service.listVMs).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByText("table-refresh"));
    await vi.waitFor(() => expect(service.listVMs).toHaveBeenCalledTimes(2));

    fireEvent.click(screen.getByText("form-success"));
    await vi.waitFor(() => expect(service.listVMs).toHaveBeenCalledTimes(3));
  });

  it("opens the create form from the Create VM button", async () => {
    service.listVMs.mockResolvedValue(ok([]));
    render(<VMsPage />);
    await rows();

    expect(screen.getByTestId("vm-form").getAttribute("data-open")).toBe("false");
    fireEvent.click(screen.getByText("Create VM"));
    expect(screen.getByTestId("vm-form").getAttribute("data-open")).toBe("true");
  });
});
