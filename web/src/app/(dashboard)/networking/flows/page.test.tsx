import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";

// #1844: the page lists the first bridge's OpenFlow rules through useSDN
// (network boundary, mocked here), formats match/actions/bytes/duration in
// the table cells and adds or deletes flows.

const { sdn, toast } = vi.hoisted(() => ({
  sdn: { listBridges: vi.fn(), listFlows: vi.fn(), addFlow: vi.fn(), deleteFlow: vi.fn() },
  toast: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useSDN: () => sdn,
}));

vi.mock("@/hooks/use-toast", () => ({ useToast: () => ({ toast }) }));

type Row = Record<string, unknown> & { id: string };
type Column = { id?: string; accessorKey?: string; cell?: (ctx: { row: { getValue: (k: string) => unknown; original: Row } }) => ReactNode };
type Action = { label: string; onClick: (rows: Row[]) => void };

// The table renders each column's own cell renderer, so the page's
// formatting is what the test reads; selection and paging are the table's.
vi.mock("@/components/ui/data-table", () => ({
  createSelectColumn: () => ({ id: "select" }),
  DataTable: ({ columns, data, bulkActions }: { columns: Column[]; data: Row[]; bulkActions: Action[] }) => (
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
      {bulkActions.map((a) => (
        <button key={a.label} onClick={() => a.onClick(data)}>
          bulk-{a.label}
        </button>
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

import OpenFlowsPage from "./page";

const flowWeb = {
  id: "f1",
  createdAt: "2026-11-01T00:00:00Z",
  config: {
    metadata: { name: "web", cookie: "0x1" },
    priority: 200,
    match: { inPort: "1", ethType: "0x0800", ipDst: "10.0.0.5", tcpDst: 443 },
    actions: [
      { type: "FLOW_ACTION_OUTPUT", port: 2 },
      { type: "FLOW_ACTION_SET_FIELD", vlanId: 100 },
      { type: "FLOW_ACTION_GOTO_TABLE", tableId: 3 },
      { type: "FLOW_ACTION_SET_FIELD", field: "ip_dscp", value: "46" },
      { type: "FLOW_ACTION_DROP" },
    ],
  },
  stats: { packetCount: "1500000", byteCount: "2048", durationSeconds: 3720 },
};

const flowBare = { id: "f2", stats: { durationSeconds: 300 } };

function cell(rowId: string, col: string): string {
  const row = screen.getByTestId(`row-${rowId}`);
  return (row.querySelector(`[data-col="${col}"]`) as HTMLElement).textContent ?? "";
}

function statValue(label: string): string {
  const card = screen.getByText(label).parentElement as HTMLElement;
  return (card.lastElementChild as HTMLElement).textContent ?? "";
}

function withFlows(flows: unknown[]) {
  sdn.listBridges.mockResolvedValue({ data: { bridges: [{ id: "br-int" }, { id: "br-ex" }] } });
  sdn.listFlows.mockResolvedValue({ data: { flows } });
}

beforeEach(() => {
  for (const fn of Object.values(sdn)) fn.mockReset();
  toast.mockReset();
});

afterEach(() => {
  cleanup();
});

describe("OpenFlowsPage", () => {
  it("loads the first bridge's flows and formats every cell", async () => {
    withFlows([flowWeb, flowBare]);
    render(<OpenFlowsPage />);

    await screen.findByTestId("row-f1");
    expect(sdn.listFlows).toHaveBeenCalledWith({ bridgeId: "br-int" });
    expect(cell("f1", "name")).toBe("web0x1");
    expect(cell("f1", "switch")).toBe("br-int");
    expect(cell("f1", "table")).toBe("T0");
    expect(cell("f1", "priority")).toBe("200");
    expect(cell("f1", "match")).toBe("in_port=1, eth_type=0x0800, ip_dst=10.0.0.5, tcp_dst=443");
    expect(cell("f1", "actions")).toBe("output(2), set_field(vlan:100), goto_table(table:3), set_field(ip_dscp=46), drop");
    expect(cell("f1", "status")).toBe("active");
    expect(cell("f1", "packets")).toBe((1500000).toLocaleString());
    expect(cell("f1", "bytes")).toBe("2 KB");
    expect(cell("f1", "duration")).toBe("1h 2m");
  });

  it("falls back to the id, wildcard match and empty actions for a bare flow", async () => {
    withFlows([flowWeb, flowBare]);
    render(<OpenFlowsPage />);

    await screen.findByTestId("row-f2");
    expect(cell("f2", "name")).toBe("f2");
    expect(cell("f2", "priority")).toBe("0");
    expect(cell("f2", "match")).toBe("*");
    expect(cell("f2", "actions")).toBe("");
    expect(cell("f2", "bytes")).toBe("0 B");
    expect(cell("f2", "duration")).toBe("5m");
  });

  it("totals the stat cards", async () => {
    withFlows([flowWeb, flowBare]);
    render(<OpenFlowsPage />);

    await screen.findByTestId("row-f1");
    expect(statValue("Total Rules")).toBe("2");
    expect(statValue("Active")).toBe("2");
    expect(statValue("Inactive")).toBe("0");
    expect(statValue("Errors")).toBe("0");
    expect(statValue("Total Packets")).toBe("1.5M");
    expect(statValue("Total Traffic")).toBe("2 KB");
  });

  it("shows a zero-duration flow as a dash", async () => {
    withFlows([{ id: "f3", stats: { durationSeconds: 0 } }]);
    render(<OpenFlowsPage />);

    await screen.findByTestId("row-f3");
    expect(cell("f3", "duration")).toBe("-");
  });

  it("lists no flows and disables Add when there is no bridge", async () => {
    sdn.listBridges.mockResolvedValue({ data: { bridges: [] } });
    render(<OpenFlowsPage />);

    const add = (await screen.findByText("Add Flow Rule")).closest("button") as HTMLButtonElement;
    expect(add.disabled).toBe(true);
    expect(sdn.listFlows).not.toHaveBeenCalled();
    expect(statValue("Total Rules")).toBe("0");
    expect(statValue("Total Traffic")).toBe("0 B");
  });

  it("shows the error state and toasts when bridges fail to load, and retries", async () => {
    sdn.listBridges.mockResolvedValue({ error: { status: 500, message: "ovs down" } });
    render(<OpenFlowsPage />);

    expect(await screen.findByText("Error Loading Flows")).toBeTruthy();
    expect(screen.getByText("ovs down")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith({ title: "Error loading bridges", description: "ovs down", variant: "destructive" });

    fireEvent.click(screen.getByText("Retry"));
    await waitFor(() => expect(sdn.listBridges).toHaveBeenCalledTimes(2));
  });

  it("shows the error state and toasts when flows fail to load", async () => {
    sdn.listBridges.mockResolvedValue({ data: { bridges: [{ id: "br-int" }] } });
    sdn.listFlows.mockResolvedValue({ error: { status: 500, message: "flow dump failed" } });
    render(<OpenFlowsPage />);

    expect(await screen.findByText("flow dump failed")).toBeTruthy();
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Error loading flows", description: "flow dump failed", variant: "destructive" }),
    );
  });

  it("toasts the placeholder row actions", async () => {
    withFlows([flowWeb]);
    render(<OpenFlowsPage />);
    const row = await screen.findByTestId("row-f1");

    for (const label of ["View Details", "Edit", "Duplicate", "Deactivate"]) {
      fireEvent.click(within(row).getByText(label));
    }
    const titles = toast.mock.calls.map((c) => (c[0] as { title: string }).title);
    expect(titles).toEqual(["View Flow", "Edit Flow", "Duplicate Flow", "Toggle Flow"]);
    expect(toast).toHaveBeenCalledWith({ title: "Toggle Flow", description: 'Toggling flow "web" is not yet implemented' });
  });

  it("deletes a flow and refetches", async () => {
    withFlows([flowWeb]);
    sdn.deleteFlow.mockResolvedValue({});
    render(<OpenFlowsPage />);
    const row = await screen.findByTestId("row-f1");

    fireEvent.click(within(row).getByText("Delete"));
    await waitFor(() => expect(sdn.deleteFlow).toHaveBeenCalledWith("br-int", "f1"));
    await waitFor(() => expect(toast).toHaveBeenCalledWith({ title: "Flow Deleted", description: 'Flow "web" has been deleted' }));
    await waitFor(() => expect(sdn.listFlows).toHaveBeenCalledTimes(2));
  });

  it("toasts a failed delete", async () => {
    withFlows([flowWeb]);
    sdn.deleteFlow.mockRejectedValue(new Error("busy"));
    render(<OpenFlowsPage />);
    const row = await screen.findByTestId("row-f1");

    fireEvent.click(within(row).getByText("Delete"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Error deleting flow", description: "busy", variant: "destructive" }),
    );
  });

  it("bulk-deletes the selected flows", async () => {
    withFlows([flowWeb, flowBare]);
    sdn.deleteFlow.mockResolvedValue({});
    render(<OpenFlowsPage />);
    await screen.findByTestId("row-f1");

    fireEvent.click(screen.getByText("bulk-Delete"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Flows Deleted", description: "2 flow rules have been deleted" }),
    );
    expect(sdn.deleteFlow.mock.calls).toEqual([
      ["br-int", "f1"],
      ["br-int", "f2"],
    ]);
  });

  it("toasts a failed bulk delete with Unknown error for a non-Error", async () => {
    withFlows([flowWeb]);
    sdn.deleteFlow.mockRejectedValue("nope");
    render(<OpenFlowsPage />);
    await screen.findByTestId("row-f1");

    fireEvent.click(screen.getByText("bulk-Delete"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Error deleting flows", description: "Unknown error", variant: "destructive" }),
    );
  });

  it("toasts the bulk deactivate placeholder", async () => {
    withFlows([flowWeb]);
    render(<OpenFlowsPage />);
    await screen.findByTestId("row-f1");

    fireEvent.click(screen.getByText("bulk-Deactivate"));
    expect(toast).toHaveBeenCalledWith({ title: "Bulk Deactivate", description: "Deactivating 1 flows is not yet implemented" });
  });

  it("adds a flow with the typed priority and in-port", async () => {
    withFlows([]);
    sdn.addFlow.mockResolvedValue({});
    render(<OpenFlowsPage />);
    await waitFor(() => expect(sdn.listFlows).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByText("Add Flow Rule"));
    expect(await screen.findByText(/forwards traffic on bridge br-int/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Priority"), { target: { value: "300" } });
    fireEvent.change(screen.getByLabelText("Match: In-Port (optional)"), { target: { value: "4" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    await waitFor(() =>
      expect(sdn.addFlow).toHaveBeenCalledWith({
        config: { bridgeId: "br-int", priority: 300, match: { inPort: "4" }, actions: [{ type: "FLOW_ACTION_OUTPUT" }] },
      }),
    );
    await waitFor(() => expect(toast).toHaveBeenCalledWith({ title: "Flow rule added", variant: "success" }));
    await waitFor(() => expect(sdn.listFlows).toHaveBeenCalledTimes(2));
  });

  it("adds a match-all flow at priority 100 when the priority is invalid", async () => {
    withFlows([]);
    sdn.addFlow.mockResolvedValue({});
    render(<OpenFlowsPage />);
    await waitFor(() => expect(sdn.listFlows).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByText("Add Flow Rule"));
    fireEvent.change(await screen.findByLabelText("Priority"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    await waitFor(() =>
      expect(sdn.addFlow).toHaveBeenCalledWith({
        config: { bridgeId: "br-int", priority: 100, match: {}, actions: [{ type: "FLOW_ACTION_OUTPUT" }] },
      }),
    );
  });

  it("toasts a failed add and keeps the dialog open", async () => {
    withFlows([]);
    sdn.addFlow.mockRejectedValue(new Error("table full"));
    render(<OpenFlowsPage />);
    await waitFor(() => expect(sdn.listFlows).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByText("Add Flow Rule"));
    fireEvent.click(await screen.findByRole("button", { name: "Add" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Failed to add flow", description: "table full", variant: "destructive" }),
    );
    expect(screen.getByRole("button", { name: "Cancel" })).toBeTruthy();
  });
});
