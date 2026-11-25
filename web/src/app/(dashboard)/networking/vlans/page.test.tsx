import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
<<<<<<< HEAD

// #1845: the page reads bridges and the first bridge's VLANs through the SDN
// client. These tests stub that client (the network boundary), the toast hook
// and the Radix row-action menu (jsdom cannot open it).

const toast = vi.fn();
const sdn = {
  listBridges: vi.fn(),
  listVLANs: vi.fn(),
  createVLAN: vi.fn(),
  deleteVLAN: vi.fn(),
};

vi.mock("@/hooks/use-toast", () => ({ useToast: () => ({ toast }) }));
=======
import type { ReactNode } from "react";

// #2033 item 5: the page lists the first bridge's VLANs through useSDN
// (network boundary, mocked here), creates VLANs on that bridge, and gates
// Create VLAN and the dialog's Create on the server's capabilities.

const { sdn, toast, capability } = vi.hoisted(() => ({
  sdn: { listBridges: vi.fn(), listVLANs: vi.fn(), createVLAN: vi.fn(), deleteVLAN: vi.fn() },
  toast: vi.fn(),
  capability: vi.fn(),
}));

>>>>>>> origin/main
vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useSDN: () => sdn,
}));
<<<<<<< HEAD
vi.mock("@/components/ui/data-table-row-actions", () => ({
  DataTableRowActions: ({
    row,
    actions,
  }: {
    row: { name: string };
    actions: { label: string; onClick: (row: unknown) => void }[];
  }) => (
    <div>
      {actions.map((a) => (
        <button key={a.label} type="button" onClick={() => a.onClick(row)}>
          {`${a.label} ${row.name}`}
=======

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
>>>>>>> origin/main
        </button>
      ))}
    </div>
  ),
}));

import VLANsPage from "./page";

<<<<<<< HEAD
const bridge = { id: "br-int" };
const defaultVlan = { id: "v1", config: { vlanId: 1, name: "default" }, stats: { portCount: 4 } };
const prod = { id: "v100", config: { vlanId: 100, name: "prod", ports: ["p1"] } };
/** No name and no ports: named by its VLAN ID. */
const unnamed = { id: "v200", config: { vlanId: 200 } };
/** No config at all: VLAN ID 0, named by its id. */
const bare = { id: "v-x" };

function listed(vlans: unknown[]) {
  sdn.listBridges.mockResolvedValue({ data: { bridges: [bridge] } });
  sdn.listVLANs.mockResolvedValue({ data: { vlans } });
}

/** The figure under a stat card's title. */
function stat(title: string) {
  return screen.getByText(title).nextElementSibling?.textContent;
}

async function openCreate() {
  await screen.findByText("default");
  fireEvent.click(screen.getByRole("button", { name: "Create VLAN" }));
}

describe("VLANsPage", () => {
  beforeEach(() => {
    toast.mockReset();
    for (const fn of Object.values(sdn)) fn.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("lists the first bridge's VLANs with their ports and counts", async () => {
    listed([defaultVlan, prod, unnamed, bare]);

    render(<VLANsPage />);

    expect(await screen.findByText("prod")).toBeTruthy();
    expect(sdn.listVLANs).toHaveBeenCalledWith({ bridgeId: "br-int" });
    expect(screen.getByText("default")).toBeTruthy();
    expect(screen.getByText("VLAN 200")).toBeTruthy();
    expect(screen.getByText("VLAN v-x")).toBeTruthy();
    expect(screen.getByText("4 ports")).toBeTruthy();
    expect(screen.getByText("1 port")).toBeTruthy();
    expect(screen.getAllByText("0 ports")).toHaveLength(2);
    expect(stat("Total VLANs")).toBe("4");
    expect(stat("Layer 2")).toBe("4");
    expect(stat("Layer 3")).toBe("0");
    expect(stat("Total Ports")).toBe("5");
    expect(screen.getAllByText("active")).toHaveLength(4);
    expect(screen.getAllByText("Disabled")).toHaveLength(4);
    expect(screen.getByRole("button", { name: "Suspend prod" })).toBeTruthy();
  });

  it("disables Create VLAN and lists nothing when there is no bridge", async () => {
    sdn.listBridges.mockResolvedValue({ data: { bridges: [] } });

    render(<VLANsPage />);

    const create = (await screen.findByRole("button", { name: "Create VLAN" })) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    expect(stat("Total VLANs")).toBe("0");
    expect(sdn.listVLANs).not.toHaveBeenCalled();
  });

  it("shows the error state when the bridges cannot be listed, and retries", async () => {
    sdn.listBridges.mockRejectedValueOnce(new Error("sdn unavailable"));
    sdn.listBridges.mockResolvedValue({ data: { bridges: [bridge] } });
    sdn.listVLANs.mockResolvedValue({ data: { vlans: [prod] } });

    render(<VLANsPage />);

    expect(await screen.findByText("Error Loading VLANs")).toBeTruthy();
    expect(screen.getByText("sdn unavailable")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error loading bridges" }));

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByText("prod")).toBeTruthy();
  });

  it("shows the error state when the VLANs cannot be listed", async () => {
    sdn.listBridges.mockResolvedValue({ data: { bridges: [bridge] } });
    sdn.listVLANs.mockRejectedValue(new Error("bridge not found"));

    render(<VLANsPage />);

    expect(await screen.findByText("bridge not found")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Error loading VLANs", variant: "destructive" })
    );
  });

  it("creates a VLAN on the selected bridge and reloads the list", async () => {
    listed([defaultVlan]);
    sdn.createVLAN.mockResolvedValue({ data: {} });

    render(<VLANsPage />);
    await openCreate();

    const create = screen.getByRole("button", { name: "Create" }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("VLAN ID *"), { target: { value: "300" } });
    fireEvent.change(screen.getByLabelText("Name (optional)"), { target: { value: "lab" } });
    fireEvent.click(create);

    await waitFor(() => expect(screen.queryByLabelText("VLAN ID *")).toBeNull());
    expect(sdn.createVLAN).toHaveBeenCalledWith({ config: { vlanId: 300, name: "lab", bridgeId: "br-int" } });
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "VLAN created" }));
    await waitFor(() => expect(sdn.listVLANs).toHaveBeenCalledTimes(2));
  });

  it("sends no name when the name is left empty", async () => {
    listed([defaultVlan]);
    sdn.createVLAN.mockResolvedValue({ data: {} });

    render(<VLANsPage />);
    await openCreate();
    fireEvent.change(screen.getByLabelText("VLAN ID *"), { target: { value: "4095" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(sdn.createVLAN).toHaveBeenCalledTimes(1));
    expect(sdn.createVLAN).toHaveBeenCalledWith({ config: { vlanId: 4095, name: undefined, bridgeId: "br-int" } });
  });

  it.each(["0", "4096", "-3"])("refuses VLAN ID %s without a request", async (value) => {
    listed([defaultVlan]);

    render(<VLANsPage />);
    await openCreate();
    fireEvent.change(screen.getByLabelText("VLAN ID *"), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Invalid VLAN ID", description: "Must be 1-4095" })
    );
    expect(sdn.createVLAN).not.toHaveBeenCalled();
    expect(screen.getByLabelText("VLAN ID *")).toBeTruthy();
  });

  it("keeps the create dialog open when the VLAN is refused", async () => {
    listed([defaultVlan]);
    sdn.createVLAN.mockRejectedValue(new Error("VLAN 300 exists"));

    render(<VLANsPage />);
    await openCreate();
    fireEvent.change(screen.getByLabelText("VLAN ID *"), { target: { value: "300" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Failed to create VLAN", description: "VLAN 300 exists" })
      )
    );
    expect((screen.getByLabelText("VLAN ID *") as HTMLInputElement).value).toBe("300");
  });

  it("deletes a VLAN by its VLAN ID and reloads the list", async () => {
    listed([defaultVlan, prod]);
    sdn.deleteVLAN.mockResolvedValue({ data: {} });

    render(<VLANsPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete prod" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "VLAN Deleted", description: "VLAN 100 (prod) has been deleted" })
      )
    );
    expect(sdn.deleteVLAN).toHaveBeenCalledWith("br-int", 100);
    expect(sdn.listVLANs).toHaveBeenCalledTimes(2);
  });

  it("never deletes the default VLAN", async () => {
    listed([defaultVlan]);

    render(<VLANsPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete default" }));

    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Cannot Delete" }));
    expect(sdn.deleteVLAN).not.toHaveBeenCalled();
  });

  it("reports a refused delete", async () => {
    listed([prod]);
    sdn.deleteVLAN.mockRejectedValue("not an Error");

    render(<VLANsPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete prod" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error deleting VLAN", description: "Unknown error" })
      )
    );
  });

  it("answers view, edit, ports and suspend with a notice only", async () => {
    listed([prod]);

    render(<VLANsPage />);
    fireEvent.click(await screen.findByRole("button", { name: "View Details prod" }));
    fireEvent.click(screen.getByRole("button", { name: "Edit prod" }));
    fireEvent.click(screen.getByRole("button", { name: "Manage Ports prod" }));
    fireEvent.click(screen.getByRole("button", { name: "Suspend prod" }));

    expect(toast.mock.calls.map(([t]) => t.title)).toEqual([
      "View VLAN",
      "Edit VLAN",
      "Manage Ports",
      "Toggle VLAN",
    ]);
  });

  it("bulk deletes the selected VLANs except the default one", async () => {
    listed([defaultVlan, prod, unnamed]);
    sdn.deleteVLAN.mockResolvedValue({ data: {} });

    render(<VLANsPage />);
    await screen.findByText("prod");
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all" }));
    fireEvent.click(await screen.findByRole("button", { name: /Delete \(3\)/ }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "VLANs Deleted", description: "2 VLANs have been deleted" })
      )
    );
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Partial Delete" }));
    expect(sdn.deleteVLAN.mock.calls).toEqual([
      ["br-int", 100],
      ["br-int", 200],
    ]);
  });

  it("sends nothing when only the default VLAN is selected for bulk delete", async () => {
    listed([defaultVlan]);

    render(<VLANsPage />);
    await screen.findByText("default");
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all" }));
    fireEvent.click(await screen.findByRole("button", { name: /Delete \(1\)/ }));

    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Partial Delete" }));
    expect(sdn.deleteVLAN).not.toHaveBeenCalled();
  });

  it("reports a refused bulk delete, and bulk suspend is a notice only", async () => {
    listed([prod, unnamed]);
    sdn.deleteVLAN.mockRejectedValue(new Error("busy"));

    render(<VLANsPage />);
    await screen.findByText("prod");
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all" }));
    fireEvent.click(await screen.findByRole("button", { name: /Suspend \(2\)/ }));
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Bulk Suspend" }));

    fireEvent.click(screen.getByRole("button", { name: /Delete \(2\)/ }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error deleting VLANs", description: "busy" })
      )
    );
=======
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
>>>>>>> origin/main
  });
});
