import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";

// #2033 item 5: the page lists the first bridge's VLANs through useSDN
// (network boundary, mocked here), creates VLANs on that bridge, and gates
// Create VLAN and the dialog's Create on the server's capabilities.

const { sdn, toast, capability } = vi.hoisted(() => ({
  sdn: { listBridges: vi.fn(), listVLANs: vi.fn(), createVLAN: vi.fn(), deleteVLAN: vi.fn() },
  toast: vi.fn(),
  capability: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useSDN: () => sdn,
}));

vi.mock("@/hooks/use-toast", () => ({ useToast: () => ({ toast }) }));

// #2033 item 5: Gated reads the server's capabilities through this hook.
vi.mock("@/hooks/use-capabilities", () => ({ useCapabilities: () => ({ loading: false, error: undefined, capability }) }));

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
      {(bulkActions ?? []).map((a) => (
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

import VLANsPage from "./page";

const CREATE_OP = "POST /api/v1/sdn/bridges/{bridge_id}/vlans";

function withVLANs(vlans: unknown[]) {
  sdn.listBridges.mockResolvedValue({ data: { bridges: [{ id: "br-int" }] } });
  sdn.listVLANs.mockResolvedValue({ data: { vlans } });
}

function createVLANButton(): HTMLButtonElement {
  return screen.getByText("Create VLAN", { selector: "button" }) as HTMLButtonElement;
}

beforeEach(() => {
  for (const fn of Object.values(sdn)) fn.mockReset();
  toast.mockReset();
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
});

afterEach(() => {
  cleanup();
});

describe("VLANsPage", () => {
  it("lists the first bridge's VLANs through listVLANs", async () => {
    withVLANs([{ id: "v100", config: { vlanId: 100, name: "prod-data", bridgeId: "br-int", ports: ["1", "2"] } }]);
    render(<VLANsPage />);

    await waitFor(() => expect(sdn.listVLANs).toHaveBeenCalledWith({ bridgeId: "br-int" }));
    await screen.findByText("prod-data");
  });

  it("creates a VLAN on the selected bridge through createVLAN", async () => {
    withVLANs([]);
    sdn.createVLAN.mockResolvedValue({});
    render(<VLANsPage />);
    await waitFor(() => expect(sdn.listVLANs).toHaveBeenCalledWith({ bridgeId: "br-int" }));

    await waitFor(() => expect(createVLANButton().disabled).toBe(false));
    fireEvent.click(createVLANButton());
    fireEvent.change(await screen.findByLabelText("VLAN ID *"), { target: { value: "200" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(sdn.createVLAN).toHaveBeenCalledWith({ config: { vlanId: 200, name: undefined, bridgeId: "br-int" } }),
    );
  });

  it("withholds Create VLAN with the server's reason when POST /api/v1/sdn/bridges/{bridge_id}/vlans is not offered", async () => {
    capability.mockImplementation((op: string) =>
      op === CREATE_OP ? { enabled: false, reason: "not-configured: sdn" } : { enabled: true },
    );
    withVLANs([]);
    render(<VLANsPage />);
    await waitFor(() => expect(sdn.listVLANs).toHaveBeenCalledWith({ bridgeId: "br-int" }));

    const create = createVLANButton();
    expect(create.disabled).toBe(true);
    expect(create.getAttribute("title")).toBe("not-configured: sdn");
    expect(create.getAttribute("data-capability-op")).toBe(CREATE_OP);
    expect(create.getAttribute("data-capability-enabled")).toBe("false");

    fireEvent.click(create);
    expect(screen.queryByLabelText("VLAN ID *")).toBeNull();
    expect(sdn.createVLAN).not.toHaveBeenCalled();
  });

  it("asks the gate for POST /api/v1/sdn/bridges/{bridge_id}/vlans and leaves Create VLAN enabled when the server offers it", async () => {
    withVLANs([]);
    render(<VLANsPage />);
    await waitFor(() => expect(sdn.listVLANs).toHaveBeenCalledWith({ bridgeId: "br-int" }));

    expect(capability).toHaveBeenCalledWith(CREATE_OP);
    await waitFor(() => expect(createVLANButton().disabled).toBe(false));
    const create = createVLANButton();
    expect(create.getAttribute("data-capability-enabled")).toBe("true");

    fireEvent.click(create);
    await screen.findByLabelText("VLAN ID *");
    expect(screen.getByRole("button", { name: "Create" }).getAttribute("data-capability-op")).toBe(CREATE_OP);
  });
});
