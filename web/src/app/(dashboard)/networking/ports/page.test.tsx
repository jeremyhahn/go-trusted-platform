import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #1845: the page reads bridges and ports through the SDN client. These tests
// stub that client (the network boundary), the toast hook, and the Radix
// row-action menu and select (jsdom cannot open them).

const toast = vi.fn();
const sdn = {
  listBridges: vi.fn(),
  listPorts: vi.fn(),
  addPort: vi.fn(),
  deletePort: vi.fn(),
};

vi.mock("@/hooks/use-toast", () => ({ useToast: () => ({ toast }) }));
vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useSDN: () => sdn,
}));
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
        </button>
      ))}
    </div>
  ),
}));
vi.mock("@/components/ui/select", () => {
  // The trigger renders nothing; the mocked Select lends its id to the native select.
  const SelectTrigger = (_props: { id?: string }) => null;
  return {
    Select: ({
      value,
      onValueChange,
      children,
    }: {
      value?: string;
      onValueChange?: (v: string) => void;
      children: React.ReactNode;
    }) => {
      const trigger = React.Children.toArray(children).find(
        (c) => React.isValidElement(c) && c.type === SelectTrigger
      ) as React.ReactElement<{ id?: string }> | undefined;
      return (
        <select id={trigger?.props.id} value={value} onChange={(e) => onValueChange?.(e.target.value)}>
          {children}
        </select>
      );
    },
    SelectTrigger,
    SelectValue: () => null,
    SelectContent: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    SelectItem: ({ value, children }: { value: string; children: React.ReactNode }) => (
      <option value={value}>{children}</option>
    ),
  };
});

import SDNPortsPage from "./page";

const bridge = { id: "br-int" };

const portUp = {
  id: "p1",
  config: { name: "eth0", macAddress: "aa:bb:cc:dd:ee:01", vlan: 100 },
  status: "PORT_STATUS_UP",
  stats: { bytesReceived: "2048", bytesSent: "0", packetsReceived: "3", packetsSent: "1", errors: "0" },
  updatedAt: "2026-11-12T00:00:00Z",
};

const portBlocked = {
  id: "p2",
  config: { name: "tap0" },
  status: "PORT_STATUS_BLOCKED",
  stats: { bytesReceived: "not-a-number", bytesSent: "-5" },
};

/** A port with no config and no status: the page names it by index and calls it down. */
const portBare = { id: "p3" };

function listed(ports: unknown[]) {
  sdn.listBridges.mockResolvedValue({ data: { bridges: [bridge] } });
  sdn.listPorts.mockResolvedValue({ data: { ports } });
}

describe("SDNPortsPage", () => {
  beforeEach(() => {
    toast.mockReset();
    for (const fn of Object.values(sdn)) fn.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("lists the first bridge's ports with their state, VLAN and traffic", async () => {
    listed([portUp, portBlocked, portBare]);

    render(<SDNPortsPage />);

    expect(await screen.findByText("eth0")).toBeTruthy();
    expect(sdn.listPorts).toHaveBeenCalledWith({ bridgeId: "br-int" });
    expect(screen.getByText("aa:bb:cc:dd:ee:01")).toBeTruthy();
    expect(screen.getByText("VLAN 100")).toBeTruthy();
    expect(screen.getByText("2 KB")).toBeTruthy();
    // A port without a config is named by its index; bad counters read as zero.
    expect(screen.getByText("port-2")).toBeTruthy();
    expect(screen.getAllByText("0 B").length).toBeGreaterThanOrEqual(4);
    expect(screen.getByText("up")).toBeTruthy();
    expect(screen.getByText("blocked")).toBeTruthy();
    expect(screen.getByText("down")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Disable eth0" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Enable tap0" })).toBeTruthy();
  });

  it("does not list ports and disables Add Port when there is no bridge", async () => {
    sdn.listBridges.mockResolvedValue({ data: { bridges: [] } });

    render(<SDNPortsPage />);

    const add = (await screen.findByRole("button", { name: "Add Port" })) as HTMLButtonElement;
    expect(add.disabled).toBe(true);
    expect(sdn.listPorts).not.toHaveBeenCalled();
  });

  it("shows the error state when the bridges cannot be listed, and retries", async () => {
    sdn.listBridges.mockRejectedValueOnce(new Error("sdn unavailable"));
    sdn.listBridges.mockResolvedValue({ data: { bridges: [bridge] } });
    sdn.listPorts.mockResolvedValue({ data: { ports: [portUp] } });

    render(<SDNPortsPage />);

    expect(await screen.findByText("Error Loading Ports")).toBeTruthy();
    expect(screen.getByText("sdn unavailable")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Error loading bridges", variant: "destructive" })
    );

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByText("eth0")).toBeTruthy();
  });

  it("shows the error state when the ports cannot be listed", async () => {
    sdn.listBridges.mockResolvedValue({ data: { bridges: [bridge] } });
    sdn.listPorts.mockRejectedValue(new Error("bridge br-int not found"));

    render(<SDNPortsPage />);

    expect(await screen.findByText("bridge br-int not found")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error loading ports" }));
  });

  it("adds a port of the chosen type to the selected bridge", async () => {
    listed([portUp]);
    sdn.addPort.mockResolvedValue({ data: {} });

    render(<SDNPortsPage />);
    await screen.findByText("eth0");
    fireEvent.click(screen.getByRole("button", { name: "Add Port" }));

    const add = screen.getByRole("button", { name: "Add" }) as HTMLButtonElement;
    expect(add.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Name *"), { target: { value: "vx0" } });
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "PORT_TYPE_VXLAN" } });
    fireEvent.click(add);

    await waitFor(() => expect(screen.queryByLabelText("Name *")).toBeNull());
    expect(sdn.addPort).toHaveBeenCalledWith({
      bridgeId: "br-int",
      config: { name: "vx0", type: "PORT_TYPE_VXLAN" },
    });
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Port added" }));
    expect(sdn.listPorts).toHaveBeenCalledTimes(2);
  });

  it("keeps the add dialog open when the port is refused", async () => {
    listed([portUp]);
    sdn.addPort.mockRejectedValue(new Error("port name in use"));

    render(<SDNPortsPage />);
    await screen.findByText("eth0");
    fireEvent.click(screen.getByRole("button", { name: "Add Port" }));
    fireEvent.change(screen.getByLabelText("Name *"), { target: { value: "eth0" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Failed to add port", description: "port name in use" })
      )
    );
    expect((screen.getByLabelText("Name *") as HTMLInputElement).value).toBe("eth0");
    expect((screen.getByRole("button", { name: "Add" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("deletes a port from its bridge and reloads the list", async () => {
    listed([portUp]);
    sdn.deletePort.mockResolvedValue({ data: {} });

    render(<SDNPortsPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete eth0" }));

    await waitFor(() => expect(sdn.deletePort).toHaveBeenCalledWith("br-int", "p1"));
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Port Deleted" })));
    expect(sdn.listPorts).toHaveBeenCalledTimes(2);
  });

  it("reports a refused delete", async () => {
    listed([portUp]);
    sdn.deletePort.mockRejectedValue("not an Error");

    render(<SDNPortsPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete eth0" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error deleting port", description: "Unknown error" })
      )
    );
  });

  it("answers view, edit and toggle with a notice only", async () => {
    listed([portUp]);

    render(<SDNPortsPage />);
    fireEvent.click(await screen.findByRole("button", { name: "View Details eth0" }));
    fireEvent.click(screen.getByRole("button", { name: "Edit eth0" }));
    fireEvent.click(screen.getByRole("button", { name: "Disable eth0" }));

    expect(toast.mock.calls.map(([t]) => t.title)).toEqual(["View Port", "Edit Port", "Toggle Port"]);
    expect(sdn.deletePort).not.toHaveBeenCalled();
  });

  it("bulk deletes the selected ports", async () => {
    listed([portUp, portBlocked]);
    sdn.deletePort.mockResolvedValue({ data: {} });

    render(<SDNPortsPage />);
    await screen.findByText("eth0");
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all" }));
    fireEvent.click(await screen.findByRole("button", { name: /Delete \(2\)/ }));

    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Ports Deleted" })));
    expect(sdn.deletePort).toHaveBeenCalledWith("br-int", "p1");
    expect(sdn.deletePort).toHaveBeenCalledWith("br-int", "p2");
  });

  it("reports a refused bulk delete", async () => {
    listed([portUp, portBlocked]);
    sdn.deletePort.mockRejectedValue(new Error("busy"));

    render(<SDNPortsPage />);
    await screen.findByText("eth0");
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all" }));
    fireEvent.click(await screen.findByRole("button", { name: /Delete \(2\)/ }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error deleting ports", description: "busy" })
      )
    );
  });
});
