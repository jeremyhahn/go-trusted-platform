import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ChangeEvent, ReactNode } from "react";

// #2051: the page drives the gateway IPAM routes through the SDK gateway
// service; these tests stub useGateway(), the boundary the page crosses.

const { toast } = vi.hoisted(() => ({ toast: vi.fn() }));

vi.mock("@/hooks/use-toast", () => ({ useToast: () => ({ toast }) }));

type Reply = { success: boolean; data?: unknown; error?: { code: string; message: string; status?: number; details?: unknown } };
type Call = { op: string; args: unknown[] };
type Handler = (op: string, args: unknown[]) => Reply | undefined;

const sdk = vi.hoisted(() => ({
  calls: [] as Array<{ op: string; args: unknown[] }>,
  handler: null as null | ((op: string, args: unknown[]) => unknown),
}));

const gateway = vi.hoisted(() => {
  const op =
    (name: string) =>
    async (...args: unknown[]) => {
      sdk.calls.push({ op: name, args });
      return (
        sdk.handler?.(name, args) ?? { success: false, error: { code: "NOT_FOUND", message: "unrouted", status: 404 } }
      );
    };
  return {
    listIPAMPools: op("listIPAMPools"),
    createIPAMPool: op("createIPAMPool"),
    getIPAMPool: op("getIPAMPool"),
    updateIPAMPool: op("updateIPAMPool"),
    deleteIPAMPool: op("deleteIPAMPool"),
    listAllocations: op("listAllocations"),
  };
});

vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  useGateway: () => gateway,
}));

type Row = Record<string, unknown> & { id: string };
type Column = { id?: string; accessorKey?: string; cell?: (ctx: { row: { getValue: (k: string) => unknown; original: Row } }) => ReactNode };

// The table renders each column's own cell renderer; paging is the table's.
vi.mock("@/components/ui/data-table", () => ({
  createSelectColumn: () => ({ id: "select" }),
  DataTable: ({ columns, data }: { columns: Column[]; data: Row[] }) => (
    <div>
      {data.map((r) => (
        <div key={r.id} data-testid={`row-${r.id}`}>
          {columns
            .filter((c) => c.cell)
            .map((c, i) => (
              <div key={i} data-col={c.accessorKey ?? c.id}>
                {c.cell!({ row: { getValue: (k) => r[k], original: r } })}
              </div>
            ))}
        </div>
      ))}
    </div>
  ),
}));

vi.mock("@/components/ui/data-table-row-actions", () => ({
  DataTableRowActions: ({ row, actions }: { row: Row; actions: { label: string; onClick: (r: Row) => void }[] }) => (
    <div>
      {actions.map((a) => (
        <button key={a.label} onClick={() => a.onClick(row)}>
          {a.label}
        </button>
      ))}
    </div>
  ),
}));

// Radix Select does not open in jsdom; a native select keeps the page's
// onValueChange contract.
vi.mock("@/components/ui/select", () => ({
  Select: ({ value, onValueChange, children }: { value?: string; onValueChange: (v: string) => void; children: ReactNode }) => (
    <select aria-label="zone-filter" value={value || "__all__"} onChange={(e: ChangeEvent<HTMLSelectElement>) => onValueChange(e.target.value)}>
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  SelectItem: ({ value, children }: { value: string; children: ReactNode }) => <option value={value}>{children}</option>,
}));

import IPAMPage from "./page";

const poolA = {
  id: "pool-a",
  name: "prod",
  cidr: "10.0.0.0/24",
  gateway: "10.0.0.1",
  zone: "control-plane",
  description: "prod pool",
  total: "254",
  allocated: "127",
  available: "127",
  reserved: ["10.0.0.1/32", "10.0.0.8/30"],
  range_start: "10.0.0.50",
  range_end: "10.0.0.200",
};
const poolB = { id: "pool-b", name: "lab", cidr: "10.1.0.0/30", zone: "lab", total: "0", allocated: "0", available: "0" };

let calls: Call[];

function ok(data: unknown): Reply {
  return { success: true, data };
}

function fail(status: number, message: string, details?: unknown): Reply {
  return { success: false, error: { code: `HTTP_${status}`, message, status, ...(details ? { details } : {}) } };
}

function serve(handler: Handler) {
  sdk.handler = handler;
}

function listing(pools: unknown[], extra: Handler = () => undefined): Handler {
  return (op, args) => {
    if (op === "listIPAMPools") return ok({ pools });
    return extra(op, args);
  };
}

function cell(rowId: string, col: string): string {
  return (screen.getByTestId(`row-${rowId}`).querySelector(`[data-col="${col}"]`) as HTMLElement).textContent ?? "";
}

function input(id: string): HTMLInputElement {
  return document.getElementById(id) as HTMLInputElement;
}

beforeEach(() => {
  sdk.calls.length = 0;
  calls = sdk.calls;
  toast.mockReset();
});

afterEach(() => {
  cleanup();
  sdk.handler = null;
  vi.unstubAllGlobals();
});

describe("IPAMPage", () => {
  it("lists the pools with their window, counts and utilization", async () => {
    serve(listing([poolA, poolB]));
    render(<IPAMPage />);

    await screen.findByTestId("row-pool-a");
    expect(calls[0]).toEqual({ op: "listIPAMPools", args: [] });
    expect(cell("pool-a", "window")).toContain("10.0.0.50 – 10.0.0.200");
    expect(cell("pool-b", "window")).toContain("whole CIDR");
    expect(cell("pool-a", "counts")).toBe("127 / 254");
    expect(cell("pool-a", "available")).toBe("127");
    expect(cell("pool-a", "utilization")).toContain("50");
    // A pool with total 0 reports 0% rather than NaN.
    expect(cell("pool-b", "utilization")).toContain("0");
    expect(cell("pool-b", "utilization")).not.toContain("NaN");
  });

  it("accepts the bare daemon body as well as the payload envelope", async () => {
    serve((op) => (op === "listIPAMPools" ? ok({ code: 200, success: true, payload: { pools: [poolB] } }) : undefined));
    render(<IPAMPage />);

    expect(await screen.findByTestId("row-pool-b")).toBeTruthy();
  });

  it("shows the load error with the server's message and retries", async () => {
    let failing = true;
    serve((op) => {
      if (op !== "listIPAMPools") return undefined;
      return failing ? fail(500, "ipam store unavailable") : ok({ pools: [poolA] });
    });
    render(<IPAMPage />);

    expect(await screen.findByText("Error Loading IPAM Pools")).toBeTruthy();
    expect(screen.getByText(/ipam store unavailable/)).toBeTruthy();

    failing = false;
    fireEvent.click(screen.getByText("Retry"));
    expect(await screen.findByTestId("row-pool-a")).toBeTruthy();
  });

  it("falls back to the HTTP status when the error body is not JSON", async () => {
    serve(() => fail(502, ""));
    render(<IPAMPage />);

    expect(await screen.findByText(/HTTP 502/)).toBeTruthy();
  });

  it("filters by zone", async () => {
    serve(listing([poolA, poolB]));
    render(<IPAMPage />);
    await screen.findByTestId("row-pool-a");

    const filter = screen.getByLabelText("zone-filter") as HTMLSelectElement;
    expect(Array.from(filter.options).map((o) => o.value)).toEqual(["__all__", "control-plane", "lab"]);
    fireEvent.change(filter, { target: { value: "control-plane" } });
    await waitFor(() => expect(calls.filter((c) => c.op === "listIPAMPools")).toHaveLength(2));
    await waitFor(() => expect(screen.queryByTestId("row-pool-b")).toBeNull());
    expect(screen.getByTestId("row-pool-a")).toBeTruthy();
  });

  it("creates a pool, leaving empty optional fields out", async () => {
    serve(listing([], (op) => (op === "createIPAMPool" ? ok({}) : undefined)));
    render(<IPAMPage />);
    await waitFor(() => expect(calls).toHaveLength(1));

    fireEvent.click(screen.getByRole("button", { name: "Create Pool" }));
    expect(await screen.findByText("Create IPAM Pool")).toBeTruthy();
    fireEvent.change(input("pool-name"), { target: { value: "edge" } });
    fireEvent.change(input("pool-cidr"), { target: { value: "10.9.0.0/24" } });
    fireEvent.change(input("pool-reserved"), { target: { value: " 10.9.0.1/32 , ,10.9.0.8/30 " } });
    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Create Pool" }));

    await waitFor(() => expect(calls.find((c) => c.op === "createIPAMPool")).toBeTruthy());
    expect(calls.find((c) => c.op === "createIPAMPool")).toEqual({
      op: "createIPAMPool",
      args: [{ name: "edge", cidr: "10.9.0.0/24", reserved: ["10.9.0.1/32", "10.9.0.8/30"] }],
    });
    await waitFor(() => expect(toast).toHaveBeenCalledWith({ title: "Pool created", variant: "success" }));
    await waitFor(() => expect(calls.filter((c) => c.op === "listIPAMPools")).toHaveLength(2));
  });

  it("creates a pool through createIPAMPool, not fetch", async () => {
    const fetchSpy = vi.fn(() => Promise.reject(new Error("hand-written fetch")));
    vi.stubGlobal("fetch", fetchSpy);
    serve(listing([], (op) => (op === "createIPAMPool" ? ok({ id: "pool-c" }) : undefined)));
    render(<IPAMPage />);
    await waitFor(() => expect(calls).toHaveLength(1));

    fireEvent.click(screen.getByRole("button", { name: "Create Pool" }));
    await screen.findByText("Create IPAM Pool");
    fireEvent.change(input("pool-name"), { target: { value: "core" } });
    fireEvent.change(input("pool-cidr"), { target: { value: "10.8.0.0/24" } });
    fireEvent.change(input("pool-zone"), { target: { value: "provisioning" } });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create Pool" }));

    await waitFor(() =>
      expect(calls.filter((c) => c.op === "createIPAMPool")).toEqual([
        { op: "createIPAMPool", args: [{ name: "core", cidr: "10.8.0.0/24", zone: "provisioning" }] },
      ]),
    );
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("disables create, edit and delete with the reason when the gateway IPAM is not configured", async () => {
    serve((op) =>
      op === "listIPAMPools"
        ? fail(503, "gateway service not configured", { reason: "SERVICE_NOT_CONFIGURED" })
        : undefined,
    );
    render(<IPAMPage />);

    expect(await screen.findByText(/IPAM is not available on this node/)).toBeTruthy();
    const create = screen.getByRole("button", { name: "Create Pool" }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    expect(screen.getAllByText(/gateway service not configured/).length).toBeGreaterThan(0);
    fireEvent.click(create);
    expect(screen.queryByText("Create IPAM Pool")).toBeNull();
    expect(calls.some((c) => c.op !== "listIPAMPools")).toBe(false);
  });

  it("does not create a pool without a name and CIDR", async () => {
    serve(listing([]));
    render(<IPAMPage />);
    await waitFor(() => expect(calls).toHaveLength(1));

    fireEvent.click(screen.getByRole("button", { name: "Create Pool" }));
    await screen.findByText("Create IPAM Pool");
    fireEvent.change(input("pool-name"), { target: { value: "   " } });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create Pool" }));

    await new Promise((r) => setTimeout(r, 20));
    expect(calls.some((c) => c.op === "createIPAMPool")).toBe(false);
  });

  it("toasts a failed create with the server's error", async () => {
    serve(listing([], (op) => (op === "createIPAMPool" ? fail(409, "CIDR overlaps pool-a") : undefined)));
    render(<IPAMPage />);
    await waitFor(() => expect(calls).toHaveLength(1));

    fireEvent.click(screen.getByRole("button", { name: "Create Pool" }));
    await screen.findByText("Create IPAM Pool");
    fireEvent.change(input("pool-name"), { target: { value: "dup" } });
    fireEvent.change(input("pool-cidr"), { target: { value: "10.0.0.0/25" } });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create Pool" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Failed to create pool", description: "CIDR overlaps pool-a", variant: "destructive" }),
    );
    expect(screen.getByText("Create IPAM Pool")).toBeTruthy();
  });

  it("edits a pool: prefills the form and PUTs every field but the CIDR", async () => {
    serve(listing([poolA], (op) => (op === "updateIPAMPool" ? ok({}) : undefined)));
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-a");

    fireEvent.click(within(row).getByText("Edit"));
    expect(await screen.findByText("Edit Pool: prod")).toBeTruthy();
    expect(input("pool-reserved").value).toBe("10.0.0.1/32, 10.0.0.8/30");
    expect(input("pool-range-start").value).toBe("10.0.0.50");
    fireEvent.change(input("pool-range-end"), { target: { value: "  " } });
    fireEvent.change(input("pool-range-start"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));

    await waitFor(() => expect(calls.find((c) => c.op === "updateIPAMPool")).toBeTruthy());
    expect(calls.find((c) => c.op === "updateIPAMPool")).toEqual({
      op: "updateIPAMPool",
      args: [
        "pool-a",
        {
          name: "prod",
          gateway: "10.0.0.1",
          zone: "control-plane",
          description: "prod pool",
          reserved: ["10.0.0.1/32", "10.0.0.8/30"],
          range_start: "",
          range_end: "",
        },
      ],
    });
    await waitFor(() => expect(toast).toHaveBeenCalledWith({ title: "Pool updated", variant: "success" }));
  });

  it("prefills empty strings for a pool with no optional fields and toasts a failed update", async () => {
    serve(listing([poolB], (op) => (op === "updateIPAMPool" ? fail(500, "") : undefined)));
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-b");

    fireEvent.click(within(row).getByText("Edit"));
    await screen.findByText("Edit Pool: lab");
    expect(input("pool-gateway").value).toBe("");
    expect(input("pool-reserved").value).toBe("");
    fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Failed to update pool", description: "HTTP 500", variant: "destructive" }),
    );
  });

  it("deletes a pool after confirmation", async () => {
    serve(listing([poolA], (op) => (op === "deleteIPAMPool" ? ok(undefined) : undefined)));
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-a");

    fireEvent.click(within(row).getByText("Delete"));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Delete Pool: prod")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(calls.find((c) => c.op === "deleteIPAMPool")?.args).toEqual(["pool-a"]));
    await waitFor(() => expect(toast).toHaveBeenCalledWith({ title: "Pool deleted", variant: "success" }));
    await waitFor(() => expect(screen.queryByText("Delete Pool: prod")).toBeNull());
  });

  it("shows a failed delete inside the dialog and clears it on Cancel", async () => {
    serve(listing([poolA], (op) => (op === "deleteIPAMPool" ? fail(409, "pool has allocations") : undefined)));
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-a");

    fireEvent.click(within(row).getByText("Delete"));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete" }));

    expect(await within(dialog).findByText("Delete Failed")).toBeTruthy();
    expect(within(dialog).getByText("pool has allocations")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByText("Delete Pool: prod")).toBeNull());
  });

  it("lists a pool's allocations", async () => {
    serve(
      listing([poolA], (op) =>
        op === "listAllocations"
          ? ok({
              allocations: [
                { ip: "10.0.0.51", pool_id: "pool-a", device_id: "dev-1", hostname: "node-1", allocated_at: "2026-11-01T00:00:00Z", expires_at: "" },
              ],
            })
          : undefined,
      ),
    );
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-a");

    fireEvent.click(within(row).getByText("View Allocations"));
    expect(await screen.findByText("10.0.0.51")).toBeTruthy();
    expect(screen.getByText(/Allocations: prod \(10\.0\.0\.0\/24\)/)).toBeTruthy();
    expect(calls.some((c) => c.op === "listAllocations" && JSON.stringify(c.args) === JSON.stringify([{ poolId: "pool-a" }]))).toBe(true);
  });

  it("shows no allocations for an empty pool", async () => {
    serve(listing([poolB], (op) => (op === "listAllocations" ? ok({ allocations: [] }) : undefined)));
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-b");

    fireEvent.click(within(row).getByText("View Allocations"));
    expect(await screen.findByText("No active allocations.")).toBeTruthy();
  });

  it("toasts a failed allocations read", async () => {
    serve(listing([poolA], (op) => (op === "listAllocations" ? fail(403, "forbidden") : undefined)));
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-a");

    fireEvent.click(within(row).getByText("View Allocations"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Failed to load allocations", description: "forbidden", variant: "destructive" }),
    );
    expect(await screen.findByText("No active allocations.")).toBeTruthy();
  });
});
