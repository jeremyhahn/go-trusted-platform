import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #1844: the page lists zones through useDNS (network boundary, mocked here),
// maps each protojson Zone with readZone and creates zones from a dialog.

const { dns, toast } = vi.hoisted(() => ({
  dns: { listZones: vi.fn(), createZone: vi.fn() },
  toast: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useDNS: () => dns,
  useToast: () => ({ toast }),
}));

// The table is its own component; the page only hands it the mapped zones.
vi.mock("@/components/features/networking/dns-zone-table", () => ({
  DNSZoneTable: ({ zones, onRefresh }: { zones: { id: string; name: string; type: string; recordCount: number }[]; onRefresh: () => void }) => (
    <div data-testid="zone-table">
      {zones.map((z) => (
        <div key={z.id} data-testid="zone-row">
          {z.name}|{z.type}|{z.recordCount}
        </div>
      ))}
      <button onClick={onRefresh}>table-refresh</button>
    </div>
  ),
}));

import DNSZonesPage from "./page";

const zones = [
  { id: 1, name: "example.com.", internal: true, ttl: 3600, records: { soa: { serial: 7 }, a: [{}, {}], mx: [{}] } },
  { id: 2, name: "lab.internal.", internal: false, ttl: 300, records: { a: [{}] } },
  { id: 3, name: "empty.test.", internal: true, ttl: 0 },
];

function statValue(label: string): string {
  const card = screen.getByText(label).parentElement as HTMLElement;
  return (card.lastElementChild as HTMLElement).textContent ?? "";
}

beforeEach(() => {
  dns.listZones.mockReset();
  dns.createZone.mockReset();
  toast.mockReset();
});

afterEach(() => {
  cleanup();
});

describe("DNSZonesPage", () => {
  it("lists the zones and computes the stat cards", async () => {
    dns.listZones.mockResolvedValue({ data: { zones } });
    render(<DNSZonesPage />);

    await waitFor(() => expect(screen.getAllByTestId("zone-row")).toHaveLength(3));
    expect(screen.getAllByTestId("zone-row").map((r) => r.textContent)).toEqual([
      "example.com.|primary|4",
      "lab.internal.|secondary|1",
      "empty.test.|primary|0",
    ]);
    expect(statValue("Total Zones")).toBe("3");
    expect(statValue("Primary")).toBe("2");
    expect(statValue("Secondary")).toBe("1");
    expect(statValue("Total Records")).toBe("5");
  });

  it("shows zero stats and an empty table when the response has no zones", async () => {
    dns.listZones.mockResolvedValue({ data: {} });
    render(<DNSZonesPage />);

    await waitFor(() => expect(screen.getByTestId("zone-table")).toBeTruthy());
    expect(screen.queryAllByTestId("zone-row")).toHaveLength(0);
    expect(statValue("Total Zones")).toBe("0");
    expect(statValue("Total Records")).toBe("0");
  });

  it("toasts the error when listing fails", async () => {
    dns.listZones.mockRejectedValue(new Error("backend down"));
    render(<DNSZonesPage />);

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: "Error",
          description: "Failed to fetch DNS zones: backend down",
          variant: "destructive",
        }),
      ),
    );
    expect(statValue("Total Zones")).toBe("0");
  });

  it("toasts the error envelope the SDK returns", async () => {
    dns.listZones.mockResolvedValue({ error: { message: "forbidden", status: 403 } });
    render(<DNSZonesPage />);

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ description: "Failed to fetch DNS zones: forbidden" }),
      ),
    );
  });

  it("refetches from the table's refresh", async () => {
    dns.listZones.mockResolvedValue({ data: { zones: [] } });
    render(<DNSZonesPage />);
    await waitFor(() => expect(screen.getByTestId("zone-table")).toBeTruthy());

    fireEvent.click(screen.getByText("table-refresh"));
    await waitFor(() => expect(dns.listZones).toHaveBeenCalledTimes(2));
  });

  it("disables Create until a zone name is typed", async () => {
    dns.listZones.mockResolvedValue({ data: { zones: [] } });
    render(<DNSZonesPage />);

    fireEvent.click(screen.getByText("Add Zone"));
    const create = await screen.findByRole("button", { name: "Create" });
    expect((create as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(screen.getByLabelText("Zone Name *"), { target: { value: "new.example" } });
    expect((create as HTMLButtonElement).disabled).toBe(false);
  });

  it("creates a zone with a trailing dot, the typed TTL and the internal flag", async () => {
    dns.listZones.mockResolvedValue({ data: { zones: [] } });
    dns.createZone.mockResolvedValue({});
    render(<DNSZonesPage />);
    await waitFor(() => expect(dns.listZones).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByText("Add Zone"));
    fireEvent.change(await screen.findByLabelText("Zone Name *"), { target: { value: "new.example" } });
    fireEvent.change(screen.getByLabelText("Default TTL (seconds)"), { target: { value: "600" } });
    fireEvent.click(screen.getByLabelText("Internal (split-horizon)"));
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(dns.createZone).toHaveBeenCalledWith({ name: "new.example.", ttl: 600, internal: false }),
    );
    await waitFor(() => expect(toast).toHaveBeenCalledWith({ title: "Zone created", variant: "success" }));
    await waitFor(() => expect(dns.listZones).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByText("Add DNS Zone")).toBeNull());
  });

  it("keeps an already-dotted name and falls back to TTL 3600 on an invalid TTL", async () => {
    dns.listZones.mockResolvedValue({ data: { zones: [] } });
    dns.createZone.mockResolvedValue({});
    render(<DNSZonesPage />);

    fireEvent.click(screen.getByText("Add Zone"));
    fireEvent.change(await screen.findByLabelText("Zone Name *"), { target: { value: "dotted.example." } });
    fireEvent.change(screen.getByLabelText("Default TTL (seconds)"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(dns.createZone).toHaveBeenCalledWith({ name: "dotted.example.", ttl: 3600, internal: true }),
    );
  });

  it("toasts the error and keeps the dialog open when creation fails", async () => {
    dns.listZones.mockResolvedValue({ data: { zones: [] } });
    dns.createZone.mockRejectedValue(new Error("zone exists"));
    render(<DNSZonesPage />);

    fireEvent.click(screen.getByText("Add Zone"));
    fireEvent.change(await screen.findByLabelText("Zone Name *"), { target: { value: "dup.example" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Failed to create zone",
        description: "zone exists",
        variant: "destructive",
      }),
    );
    expect(screen.getByText("Add DNS Zone")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Create" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("reports a non-Error rejection as Unknown error", async () => {
    dns.listZones.mockResolvedValue({ data: { zones: [] } });
    dns.createZone.mockRejectedValue("nope");
    render(<DNSZonesPage />);

    fireEvent.click(screen.getByText("Add Zone"));
    fireEvent.change(await screen.findByLabelText("Zone Name *"), { target: { value: "x.example" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "Unknown error" })),
    );
  });

  it("closes the dialog on Cancel without creating", async () => {
    dns.listZones.mockResolvedValue({ data: { zones: [] } });
    render(<DNSZonesPage />);

    fireEvent.click(screen.getByText("Add Zone"));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByText("Add DNS Zone")).toBeNull());
    expect(dns.createZone).not.toHaveBeenCalled();
  });
});
