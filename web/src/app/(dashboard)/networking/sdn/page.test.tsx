import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #1845: the page reads bridges and the first bridge's flows through the SDN
// client. These tests stub that client (the network boundary), the toast hook,
// the topology canvas and the Radix select (jsdom cannot open it).

const toast = vi.fn();
const sdn = {
  listBridges: vi.fn(),
  listFlows: vi.fn(),
  createBridge: vi.fn(),
};

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useSDN: () => sdn,
  useToast: () => ({ toast }),
}));
vi.mock("@/components/features/networking/sdn-topology", () => ({
  SDNTopology: ({ nodes }: { nodes: { id: string; name: string }[] }) => (
    <ul aria-label="topology">
      {nodes.map((n) => (
        <li key={n.id}>{`node ${n.name}`}</li>
      ))}
    </ul>
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

import SDNPage from "./page";

const ovs = { id: "br-1", config: { name: "br-prod", type: "BRIDGE_TYPE_OVS" }, status: "BRIDGE_STATUS_UP" };
/** No config and an unknown status: named by id, kind unspecified, state pending. */
const bare = { id: "br-2", status: "BRIDGE_STATUS_BOGUS" };

const flow = {
  id: "f1",
  config: {
    bridgeId: "br-1",
    table: "FLOW_TABLE_2",
    priority: 300,
    match: { inPort: 1, ethType: 2048, ipProto: 6, tcpDst: 22 },
    actions: [{ type: "FLOW_ACTION_SET_VLAN" }, { type: "FLOW_ACTION_OUTPUT", port: 2 }],
  },
  stats: { packetCount: "42", byteCount: "2048", durationSeconds: 5 },
};
/** No config and malformed counters. */
const bareFlow = { id: "f2", stats: { packetCount: "x" } };

describe("SDNPage", () => {
  beforeEach(() => {
    toast.mockReset();
    for (const fn of Object.values(sdn)) fn.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("lists the bridges, their topology and the first bridge's flow rules", async () => {
    sdn.listBridges.mockResolvedValue({ data: { bridges: [ovs, bare] } });
    sdn.listFlows.mockResolvedValue({ data: { flows: [flow, bareFlow] } });

    render(<SDNPage />);

    expect(await screen.findByText("300")).toBeTruthy();
    expect(sdn.listFlows).toHaveBeenCalledWith({ bridgeId: "br-1" });
    expect(screen.getByText("br-prod")).toBeTruthy();
    expect(screen.getByText("OVS")).toBeTruthy();
    expect(screen.getByText("active")).toBeTruthy();
    expect(screen.getByText("br-2")).toBeTruthy();
    expect(screen.getByText("Unspecified")).toBeTruthy();
    expect(screen.getByText("pending")).toBeTruthy();
    expect(screen.getByText("node br-prod")).toBeTruthy();
    expect(screen.getByText("node br-2")).toBeTruthy();
    expect(screen.getByText("mod_vlan_vid, output")).toBeTruthy();
    expect(screen.getByText('{"inPort":1,"ethType":"2048","ipProto":"6","tcpDst":22}')).toBeTruthy();
    expect(screen.getByText("42")).toBeTruthy();
    expect(screen.getByText("2.0 KB")).toBeTruthy();
    // The flow without a config: priority and table 0, no match, no actions.
    expect(screen.getByText("{}")).toBeTruthy();
    expect(screen.getByText("0.0 KB")).toBeTruthy();
  });

  it("shows only the first ten flow rules", async () => {
    const flows = Array.from({ length: 12 }, (_, i) => ({
      id: `f${i}`,
      config: { priority: 1000 + i },
    }));
    sdn.listBridges.mockResolvedValue({ data: { bridges: [ovs] } });
    sdn.listFlows.mockResolvedValue({ data: { flows } });

    render(<SDNPage />);

    expect(await screen.findByText("1009")).toBeTruthy();
    expect(screen.queryByText("1010")).toBeNull();
  });

  it("shows empty tables and asks for no flows when there is no bridge", async () => {
    sdn.listBridges.mockResolvedValue({ data: { bridges: [] } });

    render(<SDNPage />);

    expect(await screen.findByText("No networks found")).toBeTruthy();
    expect(screen.getByText("No flow rules found")).toBeTruthy();
    expect(sdn.listFlows).not.toHaveBeenCalled();
  });

  it("reports a failed bridge list and still renders the empty page", async () => {
    sdn.listBridges.mockRejectedValue(new Error("sdn unavailable"));

    render(<SDNPage />);

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: "Error",
          description: "Failed to fetch bridges: sdn unavailable",
          variant: "destructive",
        })
      )
    );
    expect(await screen.findByText("No networks found")).toBeTruthy();
  });

  it("lists the bridges when the flows cannot be read", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    sdn.listBridges.mockResolvedValue({ data: { bridges: [ovs] } });
    sdn.listFlows.mockRejectedValue(new Error("flows unavailable"));

    render(<SDNPage />);

    expect(await screen.findByText("br-prod")).toBeTruthy();
    expect(screen.getByText("No flow rules found")).toBeTruthy();
    await waitFor(() => expect(warn).toHaveBeenCalledWith("Failed to fetch flows:", "flows unavailable"));
    expect(toast).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it("creates a bridge of the chosen type and reloads the list", async () => {
    sdn.listBridges.mockResolvedValue({ data: { bridges: [] } });
    sdn.createBridge.mockResolvedValue({ data: {} });

    render(<SDNPage />);
    await screen.findByText("No networks found");
    fireEvent.click(screen.getByRole("button", { name: "Create Network" }));

    const create = screen.getByRole("button", { name: "Create" }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Name *"), { target: { value: "br-lab" } });
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "BRIDGE_TYPE_LINUX" } });
    fireEvent.click(create);

    await waitFor(() => expect(screen.queryByLabelText("Name *")).toBeNull());
    expect(sdn.createBridge).toHaveBeenCalledWith({ config: { name: "br-lab", type: "BRIDGE_TYPE_LINUX" } });
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Network created" }));
    await waitFor(() => expect(sdn.listBridges).toHaveBeenCalledTimes(2));
  });

  it("keeps the create dialog open when the bridge is refused", async () => {
    sdn.listBridges.mockResolvedValue({ data: { bridges: [] } });
    sdn.createBridge.mockRejectedValue("not an Error");

    render(<SDNPage />);
    await screen.findByText("No networks found");
    fireEvent.click(screen.getByRole("button", { name: "Create Network" }));
    fireEvent.change(screen.getByLabelText("Name *"), { target: { value: "br-lab" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Failed to create network", description: "Unknown error" })
      )
    );
    expect((screen.getByLabelText("Name *") as HTMLInputElement).value).toBe("br-lab");
    expect(sdn.listBridges).toHaveBeenCalledTimes(1);
  });
});
