import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";

// #2064: the OpenFlow rules page flushes the selected bridge's flows (behind a
// confirm) and reads one flow's counters, both through useSDN (the network
// boundary, mocked here), each behind the capability gate of its route.

const FLUSH_OP = "POST /api/v1/sdn/bridges/{name}/flows/flush";
const FLOW_STATS_OP = "GET /api/v1/sdn/bridges/{name}/flows/{flow}/stats";

const { sdn, toast, off } = vi.hoisted(() => ({
  sdn: {
    listBridges: vi.fn(),
    listFlows: vi.fn(),
    addFlow: vi.fn(),
    deleteFlow: vi.fn(),
    flushFlows: vi.fn(),
    getFlowStats: vi.fn(),
  },
  toast: vi.fn(),
  off: new Set<string>(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useSDN: () => sdn,
}));

vi.mock("@/hooks/use-toast", () => ({ useToast: () => ({ toast }) }));

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: "not-configured: sdn" } : { enabled: true },
  }),
}));

type Row = Record<string, unknown> & { id: string };
type Column = { id?: string; accessorKey?: string; cell?: (ctx: { row: { getValue: (k: string) => unknown; original: Row } }) => ReactNode };
type Action = { label: string; onClick: (rows: Row[]) => void };

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
  DataTableRowActions: ({ row, actions }: { row: Row; actions: { label: string; op?: string; onClick: (r: Row) => void }[] }) => (
    <div>
      {actions.map((a) => (
        <button key={a.label} data-op={a.op} onClick={() => a.onClick(row)}>
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
    match: { inPort: "1", ethType: "0x0800", ipDst: "192.0.2.5", tcpDst: 443 },
    actions: [{ type: "FLOW_ACTION_OUTPUT", port: 2 }],
  },
  stats: { packetCount: "1500000", byteCount: "2048", durationSeconds: 3720 },
};

function withFlows(flows: unknown[]) {
  sdn.listBridges.mockResolvedValue({ data: { bridges: [{ id: "br-int" }, { id: "br-ex" }] } });
  sdn.listFlows.mockResolvedValue({ data: { flows } });
}

async function renderLoaded() {
  render(<OpenFlowsPage />);
  await screen.findByTestId("row-f1");
}

function flushButton(): HTMLButtonElement {
  return screen.getByRole("button", { name: /Flush flows/ }) as HTMLButtonElement;
}

beforeEach(() => {
  for (const fn of Object.values(sdn)) fn.mockReset();
  toast.mockReset();
  off.clear();
});

afterEach(() => {
  cleanup();
});

describe("OpenFlowsPage flush and flow statistics", () => {
  it("gates Flush flows on the flush route and flushes only after the confirm", async () => {
    withFlows([flowWeb]);
    sdn.flushFlows.mockResolvedValue({ success: true, data: { deletedCount: 2 } });
    await renderLoaded();

    const button = flushButton();
    expect(button.getAttribute("data-capability-op")).toBe(FLUSH_OP);
    await waitFor(() => expect(button.disabled).toBe(false));
    expect(sdn.listFlows).toHaveBeenCalledTimes(1);

    fireEvent.click(button);
    expect(sdn.flushFlows).not.toHaveBeenCalled();
    expect(await screen.findByText("Flush all flows on br-int?")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Flush" }));
    await waitFor(() => expect(sdn.flushFlows).toHaveBeenCalledTimes(1));
    expect(sdn.flushFlows).toHaveBeenCalledWith({ bridgeId: "br-int" });
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "2 flows removed" })),
    );
    await waitFor(() => expect(sdn.listFlows).toHaveBeenCalledTimes(2));
  });

  it("shows a refused flush as a destructive toast", async () => {
    withFlows([flowWeb]);
    sdn.flushFlows.mockResolvedValue({ success: false, error: { status: 503, message: "sdn: not configured" } });
    await renderLoaded();

    fireEvent.click(flushButton());
    await screen.findByText("Flush all flows on br-int?");
    fireEvent.click(screen.getByRole("button", { name: "Flush" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({
          variant: "destructive",
          description: expect.stringContaining("sdn: not configured"),
        }),
      ),
    );
    expect(sdn.listFlows).toHaveBeenCalledTimes(1);
  });

  it("withholds Flush flows when the server does not offer it", async () => {
    off.add(FLUSH_OP);
    withFlows([flowWeb]);
    await renderLoaded();

    const button = flushButton();
    expect(button.disabled).toBe(true);
    expect(button.title).toBe("not-configured: sdn");
    fireEvent.click(button);
    expect(screen.queryByText("Flush all flows on br-int?")).toBeNull();
    expect(sdn.flushFlows).not.toHaveBeenCalled();
  });

  it("reads one flow's counters with Flow Statistics", async () => {
    withFlows([flowWeb]);
    sdn.getFlowStats.mockResolvedValue({
      success: true,
      data: { stats: { packetCount: "12", byteCount: "3400", durationSeconds: "61" } },
    });
    await renderLoaded();

    const action = screen.getByRole("button", { name: "Flow Statistics" });
    expect(action.getAttribute("data-op")).toBe(FLOW_STATS_OP);
    fireEvent.click(action);

    expect(await screen.findByText("Flow statistics: web")).toBeTruthy();
    expect(sdn.getFlowStats).toHaveBeenCalledWith("br-int", "f1");
    expect(await screen.findByTestId("flow-stats-packets")).toHaveProperty("textContent", "12");
    expect(screen.getByTestId("flow-stats-bytes").textContent).toBe("3400");
    expect(screen.getByTestId("flow-stats-duration").textContent).toBe("61 s");
  });

  it("shows a refused stats read in the dialog, not zeros", async () => {
    withFlows([flowWeb]);
    sdn.getFlowStats.mockResolvedValue({ success: false, error: { status: 404, message: "flow not found" } });
    await renderLoaded();

    fireEvent.click(screen.getByRole("button", { name: "Flow Statistics" }));
    await screen.findByText("Flow statistics: web");

    const error = await screen.findByTestId("flow-stats-error");
    expect(error.textContent).toContain("flow not found");
    expect(screen.queryByTestId("flow-stats-packets")).toBeNull();
    expect(screen.queryByTestId("flow-stats-bytes")).toBeNull();
    expect(screen.queryByText("0")).toBeNull();
  });
});
