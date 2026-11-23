import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ChangeEvent, ReactNode } from "react";

// #1844, #2051: the page's pools go through useSDNIPAMPools (SDNService on
// /api/v1/sdn/gateway/ipam/pools), mocked here; the allocations read is
// still a fetch, stubbed at the boundary the browser crosses. Every pool
// control is gated on its route.

const { toast } = vi.hoisted(() => ({ toast: vi.fn() }));

vi.mock("@/hooks/use-toast", () => ({ useToast: () => ({ toast }) }));

const { off } = vi.hoisted(() => ({ off: new Set<string>() }));

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: "not-configured: gateway" } : { enabled: true },
  }),
}));

type HookState = {
  pools: unknown[];
  isLoading: boolean;
  error: string | null;
  refetch: ReturnType<typeof vi.fn>;
  create: ReturnType<typeof vi.fn>;
  update: ReturnType<typeof vi.fn>;
  remove: ReturnType<typeof vi.fn>;
};

// A small store so a test can change what the hook answers and the page
// renders again, as it would when the real hook lists again.
const store = vi.hoisted(() => {
  let state = {} as HookState;
  const listeners = new Set<() => void>();
  return {
    zones: [] as Array<string | undefined>,
    get: () => state,
    reset(next: HookState) {
      state = next;
    },
    set(patch: Partial<HookState>) {
      state = { ...state, ...patch };
      listeners.forEach((l) => l());
    },
    subscribe(l: () => void) {
      listeners.add(l);
      return () => {
        listeners.delete(l);
      };
    },
  };
});

vi.mock("@/hooks/use-sdn-ipam-pools", async () => {
  const React = await import("react");
  return {
    useSDNIPAMPools: (zone?: string) => {
      store.zones.push(zone);
      return React.useSyncExternalStore(store.subscribe, store.get);
    },
  };
});

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
  DataTableRowActions: ({ row, actions }: { row: Row; actions: { label: string; onClick: (r: Row) => void; op?: string }[] }) => (
    <div>
      {actions.map((a) => (
        <button key={a.label} data-capability-op={a.op} onClick={() => a.onClick(row)}>
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

const LIST = "GET /api/v1/sdn/gateway/ipam/pools";
const CREATE = "POST /api/v1/sdn/gateway/ipam/pools";
const UPDATE = "PUT /api/v1/sdn/gateway/ipam/pools/{id}";
const DELETE = "DELETE /api/v1/sdn/gateway/ipam/pools/{id}";

const poolA = {
  id: "pool-a",
  name: "prod",
  cidr: "192.0.2.0/24",
  gateway: "192.0.2.1",
  zone: "control-plane",
  description: "prod pool",
  total: 254,
  allocated: 127,
  available: 127,
  reserved: ["192.0.2.1/32", "192.0.2.8/30"],
  range_start: "192.0.2.50",
  range_end: "192.0.2.200",
};
const poolB = { id: "pool-b", name: "lab", cidr: "198.51.100.0/30", zone: "lab", total: 0, allocated: 0, available: 0 };

function hookWith(pools: unknown[], patch: Partial<HookState> = {}) {
  store.reset({
    pools,
    isLoading: false,
    error: null,
    refetch: vi.fn(async () => undefined),
    create: vi.fn(async () => ({})),
    update: vi.fn(async () => ({})),
    remove: vi.fn(async () => undefined),
    ...patch,
  });
  return store.get();
}

type Call = { method: string; url: string; body: unknown };
let calls: Call[];
type Handler = (method: string, url: URL, body: unknown) => Response | undefined;

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function serve(handler: Handler) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), "http://localhost");
      const method = init?.method ?? "GET";
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ method, url: url.pathname + url.search, body });
      return handler(method, url, body) ?? json(404, { error: "unrouted" });
    }),
  );
}

function cell(rowId: string, col: string): string {
  return (screen.getByTestId(`row-${rowId}`).querySelector(`[data-col="${col}"]`) as HTMLElement).textContent ?? "";
}

function input(id: string): HTMLInputElement {
  return document.getElementById(id) as HTMLInputElement;
}

function gated(op: string): HTMLButtonElement[] {
  return Array.from(document.querySelectorAll(`[data-capability-op="${op}"]`)) as HTMLButtonElement[];
}

function headerButton(name: string): HTMLButtonElement {
  return screen.getAllByRole("button", { name }).find((b) => !b.closest("[role=dialog]")) as HTMLButtonElement;
}

beforeEach(() => {
  calls = [];
  toast.mockReset();
  store.zones.length = 0;
  serve(() => undefined);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  off.clear();
});

describe("IPAMPage", () => {
  it("lists the pools with their window, counts and utilization", async () => {
    hookWith([poolA, poolB]);
    render(<IPAMPage />);

    await screen.findByTestId("row-pool-a");
    expect(store.zones[0]).toBeUndefined();
    expect(cell("pool-a", "window")).toContain("192.0.2.50 – 192.0.2.200");
    expect(cell("pool-b", "window")).toContain("whole CIDR");
    expect(cell("pool-a", "counts")).toBe("127 / 254");
    expect(cell("pool-a", "available")).toBe("127");
    expect(cell("pool-a", "utilization")).toContain("50");
    // A pool with total 0 reports 0% rather than NaN.
    expect(cell("pool-b", "utilization")).toContain("0");
    expect(cell("pool-b", "utilization")).not.toContain("NaN");
    // The pools come from the hook, not a fetch of their own.
    expect(calls.some((c) => c.url.startsWith("/api/v1/sdn/gateway/ipam/pools"))).toBe(false);
  });

  it("shows the load error with the server's message and retries", async () => {
    const hook = hookWith([], { error: "HTTP 500: ipam store unavailable" });
    hook.refetch.mockImplementation(async () => store.set({ error: null, pools: [poolA] }));
    render(<IPAMPage />);

    expect(await screen.findByText("Error Loading IPAM Pools")).toBeTruthy();
    expect(screen.getByText(/ipam store unavailable/)).toBeTruthy();

    fireEvent.click(screen.getByText("Retry"));
    expect(hook.refetch).toHaveBeenCalledTimes(1);
    expect(await screen.findByTestId("row-pool-a")).toBeTruthy();
  });

  it("filters by zone through the hook", async () => {
    hookWith([poolA, poolB]);
    render(<IPAMPage />);
    await screen.findByTestId("row-pool-a");

    const filter = screen.getByLabelText("zone-filter") as HTMLSelectElement;
    expect(Array.from(filter.options).map((o) => o.value)).toEqual(["__all__", "control-plane", "lab"]);
    fireEvent.change(filter, { target: { value: "control-plane" } });
    await waitFor(() => expect(store.zones.at(-1)).toBe("control-plane"));
  });

  it("creates a pool, leaving empty optional fields out", async () => {
    const hook = hookWith([]);
    render(<IPAMPage />);

    fireEvent.click(headerButton("Create Pool"));
    expect(await screen.findByText("Create IPAM Pool")).toBeTruthy();
    fireEvent.change(input("pool-name"), { target: { value: "edge" } });
    fireEvent.change(input("pool-cidr"), { target: { value: "192.0.2.0/24" } });
    fireEvent.change(input("pool-reserved"), { target: { value: " 192.0.2.1/32 , ,192.0.2.8/30 " } });
    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Create Pool" }));

    await waitFor(() => expect(hook.create).toHaveBeenCalledTimes(1));
    expect(hook.create).toHaveBeenCalledWith({ name: "edge", cidr: "192.0.2.0/24", reserved: ["192.0.2.1/32", "192.0.2.8/30"] });
    await waitFor(() => expect(toast).toHaveBeenCalledWith({ title: "Pool created", variant: "success" }));
    await waitFor(() => expect(screen.queryByText("Create IPAM Pool")).toBeNull());
  });

  it("does not create a pool without a name and CIDR", async () => {
    const hook = hookWith([]);
    render(<IPAMPage />);

    fireEvent.click(headerButton("Create Pool"));
    await screen.findByText("Create IPAM Pool");
    fireEvent.change(input("pool-name"), { target: { value: "   " } });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create Pool" }));

    await new Promise((r) => setTimeout(r, 20));
    expect(hook.create).not.toHaveBeenCalled();
  });

  it("toasts a failed create with the server's error", async () => {
    hookWith([], { create: vi.fn(async () => Promise.reject(new Error("HTTP 409: CIDR overlaps pool-a"))) });
    render(<IPAMPage />);

    fireEvent.click(headerButton("Create Pool"));
    await screen.findByText("Create IPAM Pool");
    fireEvent.change(input("pool-name"), { target: { value: "dup" } });
    fireEvent.change(input("pool-cidr"), { target: { value: "192.0.2.0/25" } });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create Pool" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Failed to create pool", description: "HTTP 409: CIDR overlaps pool-a", variant: "destructive" }),
    );
    expect(screen.getByText("Create IPAM Pool")).toBeTruthy();
  });

  it("edits a pool: prefills the form and PUTs every field but the CIDR", async () => {
    const hook = hookWith([poolA]);
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-a");

    fireEvent.click(within(row).getByText("Edit"));
    expect(await screen.findByText("Edit Pool: prod")).toBeTruthy();
    expect(input("pool-reserved").value).toBe("192.0.2.1/32, 192.0.2.8/30");
    expect(input("pool-range-start").value).toBe("192.0.2.50");
    fireEvent.change(input("pool-range-end"), { target: { value: "  " } });
    fireEvent.change(input("pool-range-start"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));

    await waitFor(() => expect(hook.update).toHaveBeenCalledTimes(1));
    expect(hook.update).toHaveBeenCalledWith("pool-a", {
      name: "prod",
      gateway: "192.0.2.1",
      zone: "control-plane",
      description: "prod pool",
      reserved: ["192.0.2.1/32", "192.0.2.8/30"],
      range_start: "",
      range_end: "",
    });
    await waitFor(() => expect(toast).toHaveBeenCalledWith({ title: "Pool updated", variant: "success" }));
  });

  it("prefills empty strings for a pool with no optional fields and toasts a failed update", async () => {
    hookWith([poolB], { update: vi.fn(async () => Promise.reject(new Error("HTTP 500: Internal Server Error"))) });
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-b");

    fireEvent.click(within(row).getByText("Edit"));
    await screen.findByText("Edit Pool: lab");
    expect(input("pool-gateway").value).toBe("");
    expect(input("pool-reserved").value).toBe("");
    fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Failed to update pool", description: "HTTP 500: Internal Server Error", variant: "destructive" }),
    );
  });

  it("deletes a pool after confirmation", async () => {
    const hook = hookWith([poolA]);
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-a");

    fireEvent.click(within(row).getByText("Delete"));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Delete Pool: prod")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(hook.remove).toHaveBeenCalledWith("pool-a"));
    await waitFor(() => expect(toast).toHaveBeenCalledWith({ title: "Pool deleted", variant: "success" }));
    await waitFor(() => expect(screen.queryByText("Delete Pool: prod")).toBeNull());
  });

  it("shows a failed delete inside the dialog and clears it on Cancel", async () => {
    hookWith([poolA], { remove: vi.fn(async () => Promise.reject(new Error("HTTP 409: pool has allocations"))) });
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-a");

    fireEvent.click(within(row).getByText("Delete"));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete" }));

    expect(await within(dialog).findByText("Delete Failed")).toBeTruthy();
    expect(within(dialog).getByText("HTTP 409: pool has allocations")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByText("Delete Pool: prod")).toBeNull());
  });

  it("lists a pool's allocations", async () => {
    hookWith([poolA]);
    serve((method, url) =>
      url.pathname.endsWith("/allocations")
        ? json(200, {
            payload: {
              allocations: [
                { ip: "192.0.2.51", pool_id: "pool-a", device_id: "dev-1", hostname: "node-1.example.com", allocated_at: "2026-11-01T00:00:00Z", expires_at: "" },
              ],
            },
          })
        : undefined,
    );
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-a");

    fireEvent.click(within(row).getByText("View Allocations"));
    expect(await screen.findByText("192.0.2.51")).toBeTruthy();
    expect(screen.getByText(/Allocations: prod \(192\.0\.2\.0\/24\)/)).toBeTruthy();
    expect(calls.some((c) => c.url === "/api/v1/sdn/gateway/ipam/allocations?pool_id=pool-a")).toBe(true);
  });

  it("shows no allocations for an empty pool", async () => {
    hookWith([poolB]);
    serve((method, url) => (url.pathname.endsWith("/allocations") ? json(200, { allocations: [] }) : undefined));
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-b");

    fireEvent.click(within(row).getByText("View Allocations"));
    expect(await screen.findByText("No active allocations.")).toBeTruthy();
  });

  it("toasts a failed allocations read", async () => {
    hookWith([poolA]);
    serve((method, url) => (url.pathname.endsWith("/allocations") ? json(403, { error: "forbidden" }) : undefined));
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-a");

    fireEvent.click(within(row).getByText("View Allocations"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Failed to load allocations", description: "forbidden", variant: "destructive" }),
    );
    expect(await screen.findByText("No active allocations.")).toBeTruthy();
  });
});

describe("IPAMPage capability gates", () => {
  it("gates Refresh on the list route and Create Pool on the create route", async () => {
    const hook = hookWith([poolA]);
    render(<IPAMPage />);
    await screen.findByTestId("row-pool-a");

    const [refresh] = gated(LIST);
    expect(refresh).toBeDefined();
    expect(refresh.getAttribute("aria-label")).toBe("Refresh pools");
    expect(refresh.getAttribute("data-capability-enabled")).toBe("true");
    fireEvent.click(refresh);
    expect(hook.refetch).toHaveBeenCalledTimes(1);

    expect(headerButton("Create Pool").getAttribute("data-capability-op")).toBe(CREATE);
  });

  it("withholds Refresh and Create Pool when the server does not offer them", async () => {
    off.add(LIST);
    off.add(CREATE);
    hookWith([poolA]);
    render(<IPAMPage />);
    await screen.findByTestId("row-pool-a");

    const [refresh] = gated(LIST);
    expect(refresh.disabled).toBe(true);
    expect(refresh.getAttribute("title")).toBe("not-configured: gateway");
    const create = headerButton("Create Pool");
    expect(create.getAttribute("data-capability-enabled")).toBe("false");
    expect(create.disabled).toBe(true);
    expect(create.getAttribute("title")).toBe("not-configured: gateway");
  });

  it("gates the Edit and Delete row actions on their routes", async () => {
    hookWith([poolA]);
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-a");

    expect(within(row).getByText("Edit").getAttribute("data-capability-op")).toBe(UPDATE);
    expect(within(row).getByText("Delete").getAttribute("data-capability-op")).toBe(DELETE);
    expect(within(row).getByText("View Allocations").hasAttribute("data-capability-op")).toBe(false);
  });

  it("gates the form's save on create in create mode and on update in edit mode", async () => {
    hookWith([poolA]);
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-a");

    fireEvent.click(headerButton("Create Pool"));
    let dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("button", { name: "Create Pool" }).getAttribute("data-capability-op")).toBe(CREATE);
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByText("Create IPAM Pool")).toBeNull());

    fireEvent.click(within(row).getByText("Edit"));
    dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("button", { name: "Save Changes" }).getAttribute("data-capability-op")).toBe(UPDATE);
  });

  it("withholds the edit save when update is not offered", async () => {
    off.add(UPDATE);
    const hook = hookWith([poolA]);
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-a");

    fireEvent.click(within(row).getByText("Edit"));
    const save = (await screen.findByRole("button", { name: "Save Changes" })) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    expect(save.getAttribute("title")).toBe("not-configured: gateway");
    fireEvent.click(save);
    await new Promise((r) => setTimeout(r, 20));
    expect(hook.update).not.toHaveBeenCalled();
  });

  it("gates the delete confirm on the delete route and withholds it when not offered", async () => {
    off.add(DELETE);
    const hook = hookWith([poolA]);
    render(<IPAMPage />);
    const row = await screen.findByTestId("row-pool-a");

    fireEvent.click(within(row).getByText("Delete"));
    const dialog = await screen.findByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: "Delete" }) as HTMLButtonElement;
    expect(confirm.getAttribute("data-capability-op")).toBe(DELETE);
    expect(confirm.disabled).toBe(true);
    expect(confirm.getAttribute("title")).toBe("not-configured: gateway");
    fireEvent.click(confirm);
    await new Promise((r) => setTimeout(r, 20));
    expect(hook.remove).not.toHaveBeenCalled();
  });
});
