import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #1845: the page reads and writes zones with fetch against the zones REST
// path. These tests stub fetch (the network boundary), the toast hook, and the
// Radix row-action menu and select (jsdom cannot open them).

const toast = vi.fn();

vi.mock("@/hooks/use-toast", () => ({ useToast: () => ({ toast }) }));
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
  // The trigger renders nothing; the mocked Select names the native select
  // after the placeholder of the trigger's value.
  const SelectValue = (props: { placeholder?: string }) => (props.placeholder ? null : null);
  const SelectTrigger = (props: { children?: React.ReactNode }) => (props.children ? null : null);
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
      ) as React.ReactElement<{ children?: React.ReactNode }> | undefined;
      const valueEl = trigger?.props.children as React.ReactElement<{ placeholder?: string }> | undefined;
      return (
        <select
          aria-label={valueEl?.props.placeholder}
          value={value}
          onChange={(e) => onValueChange?.(e.target.value)}
        >
          {children}
        </select>
      );
    },
    SelectTrigger,
    SelectValue,
    SelectContent: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    SelectItem: ({ value, children }: { value: string; children: React.ReactNode }) => (
      <option value={value}>{children}</option>
    ),
  };
});

import ZonesPage from "./page";

const updated = "2026-11-12T08:00:00Z";

const fabric = {
  name: "fabric",
  offset: 1,
  port_classes: ["fabric"],
  internet_ingress: false,
  isolate_from: [],
  allow_to: [],
  services: [],
  isolate: false,
  oob: false,
  lifecycle_role: "",
  numbering: { vlan: 101, subnet4: "fabric-subnet", gateway: "fabric-gw" },
  restart_required: false,
  created_at: updated,
  updated_at: updated,
};

const lab = {
  name: "lab/1",
  offset: 12,
  port_classes: ["gateway"],
  internet_ingress: true,
  isolate_from: ["fabric"],
  allow_to: [{ zone: "fabric", services: ["ssh"] }],
  services: ["http", "dns"],
  isolate: true,
  oob: true,
  lifecycle_role: "quarantine",
  privileged_access: { reason: "audit", approved_by: "owner" },
  restart_required: true,
  created_at: updated,
  updated_at: "",
};

/** A zone the API sent with its lists and offset left out. */
const sparse = { name: "dmz", lifecycle_role: "" } as unknown as typeof fabric;

type Route = { status?: number; body?: unknown; raw?: string };

const fetchMock = vi.fn();
let routes: Record<string, Route[]> = {};

/** Queue the answers one method and path give, in order; the last one repeats. */
function on(method: string, path: string, ...answers: Route[]) {
  routes[`${method} ${path}`] = answers;
}

function calls(method: string, path: string) {
  return fetchMock.mock.calls.filter(
    ([url, init]) => String(url) === path && ((init as RequestInit | undefined)?.method ?? "GET") === method
  );
}

function sentBody(method: string, path: string) {
  const [, init] = calls(method, path).at(-1) ?? [];
  return JSON.parse(String((init as RequestInit).body));
}

function stat(title: string) {
  return screen.getByText(title, { selector: "div" }).nextElementSibling?.textContent;
}

/** Matches a removable tag badge: its name, then a ×. */
function badge(name: string) {
  return (_: string, el: Element | null) => !!el?.classList.contains("cursor-pointer") && el.textContent === `${name} ×`;
}

function dialog() {
  return within(screen.getByRole("dialog"));
}

describe("ZonesPage", () => {
  beforeEach(() => {
    toast.mockReset();
    routes = {};
    fetchMock.mockReset();
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      const key = `${init?.method ?? "GET"} ${url}`;
      const queue = routes[key];
      if (!queue) throw new Error(`unexpected ${key}`);
      const answer = queue.length > 1 ? queue.shift()! : queue[0];
      const status = answer.status ?? 200;
      // A 204 may carry no body at all.
      const body = status === 204 ? null : (answer.raw ?? JSON.stringify(answer.body ?? {}));
      return new Response(body, { status });
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("lists the zones in the webservice wrapper with their counts, numbering and flags", async () => {
    on("GET", "/api/v1/sdn/zones", { body: { payload: { zones: [fabric, lab, sparse] } } });

    render(<ZonesPage />);

    expect(await screen.findByText("lab/1")).toBeTruthy();
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/sdn/zones", { credentials: "include" });
    expect(stat("Total")).toBe("3");
    expect(stat("Built-in")).toBe("1");
    expect(stat("Custom")).toBe("2");
    expect(stat("Lifecycle Roles")).toBe("1");
    expect(stat("Isolated")).toBe("1");
    expect(screen.getAllByText("built-in")).toHaveLength(1);
    expect(screen.getByText("x01")).toBeTruthy();
    expect(screen.getByText("x12")).toBeTruthy();
    // A zone without an offset reads as x00.
    expect(screen.getByText("x00")).toBeTruthy();
    expect(screen.getByText("101 · fabric-subnet")).toBeTruthy();
    expect(screen.getByText(new Date(updated).toLocaleString())).toBeTruthy();
    for (const flag of [
      "internet-ingress",
      "isolate",
      "oob",
      "privileged-access",
      "isolate-from(1)",
      "allow-to(1)",
      "services(2)",
    ]) {
      expect(screen.getByText(flag)).toBeTruthy();
    }
    expect(screen.getAllByText("default")).toHaveLength(2);
    expect(screen.getByRole("button", { name: "Override (Edit) fabric" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Edit lab/1" })).toBeTruthy();
  });

  it("accepts the bare body the daemon sends, and a body with no zones", async () => {
    on("GET", "/api/v1/sdn/zones", { body: { zones: [lab] } }, { body: {} });

    render(<ZonesPage />);

    expect(await screen.findByText("lab/1")).toBeTruthy();
    expect(stat("Total")).toBe("1");

    cleanup();
    render(<ZonesPage />);

    expect(await screen.findByText("Network Zones", { selector: "h1" })).toBeTruthy();
    expect(stat("Total")).toBe("0");
  });

  it("says it is loading until the first answer", async () => {
    let answer: (r: Response) => void = () => {};
    fetchMock.mockImplementationOnce(() => new Promise<Response>((r) => (answer = r)));

    render(<ZonesPage />);

    expect(screen.getByText("Loading zones...")).toBeTruthy();
    answer(new Response(JSON.stringify({ zones: [] })));
    expect(await screen.findByText("Network Zones", { selector: "h1" })).toBeTruthy();
  });

  it("shows the server's error, and retries", async () => {
    on(
      "GET",
      "/api/v1/sdn/zones",
      { status: 503, body: { error: "zone store unavailable" } },
      { body: { zones: [fabric] } }
    );

    render(<ZonesPage />);

    expect(await screen.findByText("Error Loading Zones")).toBeTruthy();
    expect(screen.getByText("zone store unavailable")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByText("fabric")).toBeTruthy();
  });

  it("shows the HTTP status when the error body is not JSON", async () => {
    on("GET", "/api/v1/sdn/zones", { status: 500, raw: "<html>oops</html>" });

    render(<ZonesPage />);

    expect(await screen.findByText("HTTP 500")).toBeTruthy();
  });

  it("shows a fetch that throws", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("network down"));

    render(<ZonesPage />);

    expect(await screen.findByText("network down")).toBeTruthy();
  });

  it("creates a zone with the defaults when only a name is given", async () => {
    on("GET", "/api/v1/sdn/zones", { body: { zones: [fabric] } });
    on("POST", "/api/v1/sdn/zones", { status: 201, body: {} });

    render(<ZonesPage />);
    await screen.findByText("fabric");
    fireEvent.click(screen.getByRole("button", { name: "Create Zone" }));

    const submit = dialog().getByRole("button", { name: "Create Zone" }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    fireEvent.change(dialog().getByLabelText("Name *"), { target: { value: "   " } });
    expect(submit.disabled).toBe(true);
    fireEvent.change(dialog().getByLabelText("Name *"), { target: { value: "lab" } });
    fireEvent.click(submit);

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(sentBody("POST", "/api/v1/sdn/zones")).toEqual({
      name: "lab",
      offset: 9,
      port_classes: ["hypervisor"],
      internet_ingress: false,
      isolate_from: [],
      allow_to: [],
      services: [],
      isolate: true,
      oob: false,
      lifecycle_role: "",
    });
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Zone created" }));
    await waitFor(() => expect(calls("GET", "/api/v1/sdn/zones")).toHaveLength(2));
  });

  it("creates a zone with every policy field filled in", async () => {
    on("GET", "/api/v1/sdn/zones", { body: { zones: [fabric, lab] } });
    on("POST", "/api/v1/sdn/zones", { body: {} });

    render(<ZonesPage />);
    await screen.findByText("fabric");
    fireEvent.click(screen.getByRole("button", { name: "Create Zone" }));
    const d = dialog();

    fireEvent.change(d.getByLabelText("Name *"), { target: { value: "edge" } });
    fireEvent.change(d.getByLabelText("Offset (9-99)"), { target: { value: "42" } });
    fireEvent.click(d.getByRole("switch", { name: "gateway" }));
    fireEvent.click(d.getByRole("switch", { name: "hypervisor" }));
    fireEvent.click(d.getByRole("switch", { name: /^Internet Ingress/ }));
    fireEvent.click(d.getByRole("switch", { name: /^Isolate/ }));

    // isolate_from: Add stays off until a zone is picked; a badge click removes it.
    const isolateFrom = d.getByLabelText("Select zone to exclude...");
    const [addIsolate, addService] = d.getAllByRole("button", { name: "Add" }) as HTMLButtonElement[];
    expect(addIsolate.disabled).toBe(true);
    fireEvent.change(isolateFrom, { target: { value: "lab/1" } });
    fireEvent.click(addIsolate);
    fireEvent.change(isolateFrom, { target: { value: "fabric" } });
    fireEvent.click(addIsolate);
    fireEvent.click(d.getByText(badge("lab/1")));
    expect(d.queryByText(badge("lab/1"))).toBeNull();
    expect(d.getByText(badge("fabric"))).toBeTruthy();

    // allow_to: two rows, the second removed; the first's services parse on blur.
    fireEvent.click(d.getByRole("button", { name: "Add Egress Path" }));
    fireEvent.click(d.getByRole("button", { name: "Add Egress Path" }));
    const [row1] = d.getAllByLabelText("Select zone...");
    fireEvent.change(row1, { target: { value: "fabric" } });
    // A zone chosen in one row is not offered in another.
    const row2 = d.getAllByLabelText("Select zone...")[1];
    expect(within(row2).queryByRole("option", { name: "fabric" })).toBeNull();
    const [svc1] = d.getAllByPlaceholderText("services (CSV, empty = all)");
    fireEvent.change(svc1, { target: { value: " ssh, , https " } });
    fireEvent.blur(svc1);
    fireEvent.click(d.getAllByRole("button", { name: "Remove allow_to entry" })[1]);

    // Services commit on Enter, comma, blur and Add; duplicates and blanks drop.
    const services = d.getByPlaceholderText("e.g. ssh, http, postgres");
    expect(addService.disabled).toBe(true);
    fireEvent.change(services, { target: { value: "ssh, http" } });
    fireEvent.keyDown(services, { key: "Enter" });
    fireEvent.change(services, { target: { value: "http" } });
    fireEvent.keyDown(services, { key: "," });
    fireEvent.change(services, { target: { value: "dns" } });
    fireEvent.blur(services);
    fireEvent.change(services, { target: { value: " , " } });
    fireEvent.keyDown(services, { key: "Enter" });
    fireEvent.change(services, { target: { value: "ntp" } });
    fireEvent.keyDown(services, { key: "a" });
    fireEvent.click(addService);
    fireEvent.click(d.getByText(badge("dns")));

    fireEvent.change(d.getByPlaceholderText("Reason"), { target: { value: "jump host" } });
    fireEvent.click(d.getByRole("button", { name: "Create Zone" }));

    await waitFor(() => expect(calls("POST", "/api/v1/sdn/zones")).toHaveLength(1));
    expect(sentBody("POST", "/api/v1/sdn/zones")).toEqual({
      name: "edge",
      offset: 42,
      port_classes: ["gateway"],
      internet_ingress: true,
      isolate_from: ["fabric"],
      allow_to: [{ zone: "fabric", services: ["ssh", "https"] }],
      services: ["ssh", "http", "ntp"],
      isolate: false,
      oob: false,
      lifecycle_role: "",
      privileged_access: { reason: "jump host", approved_by: "" },
    });
  });

  it("keeps the create dialog open when the zone is refused", async () => {
    on("GET", "/api/v1/sdn/zones", { body: { zones: [] } });
    on("POST", "/api/v1/sdn/zones", { status: 400, body: { error: "offset 9 in use" } });

    render(<ZonesPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Create Zone" }));
    fireEvent.change(dialog().getByLabelText("Name *"), { target: { value: "lab" } });
    fireEvent.click(dialog().getByRole("button", { name: "Create Zone" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: "Failed to create zone",
          description: "offset 9 in use",
          variant: "destructive",
        })
      )
    );
    expect((dialog().getByLabelText("Name *") as HTMLInputElement).value).toBe("lab");
    expect(calls("GET", "/api/v1/sdn/zones")).toHaveLength(1);
  });

  it("edits a custom zone by its encoded name and sends no name", async () => {
    on("GET", "/api/v1/sdn/zones", { body: { zones: [fabric, lab, sparse] } });
    on("PUT", "/api/v1/sdn/zones/lab%2F1", { body: {} });

    render(<ZonesPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Edit lab/1" }));

    expect(dialog().getByText("Edit Zone: lab/1")).toBeTruthy();
    expect(dialog().queryByLabelText("Name *")).toBeNull();
    expect((dialog().getByLabelText("Offset (9-99)") as HTMLInputElement).value).toBe("12");
    expect((dialog().getByPlaceholderText("Approved by") as HTMLInputElement).value).toBe("owner");
    expect(dialog().getAllByLabelText("Select zone...")).toHaveLength(1);
    fireEvent.change(dialog().getByPlaceholderText("Approved by"), { target: { value: "ops" } });
    fireEvent.click(dialog().getByRole("button", { name: "Save Changes" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(sentBody("PUT", "/api/v1/sdn/zones/lab%2F1")).toEqual({
      offset: 12,
      port_classes: ["gateway"],
      internet_ingress: true,
      isolate_from: ["fabric"],
      allow_to: [{ zone: "fabric", services: ["ssh"] }],
      services: ["http", "dns"],
      isolate: true,
      oob: true,
      lifecycle_role: "quarantine",
      privileged_access: { reason: "audit", approved_by: "ops" },
    });
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Zone updated" }));
  });

  it("edits a zone the API sent without its lists", async () => {
    on("GET", "/api/v1/sdn/zones", { body: { zones: [sparse] } });
    on("PUT", "/api/v1/sdn/zones/dmz", { body: {} });

    render(<ZonesPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Edit dmz" }));
    fireEvent.click(dialog().getByRole("button", { name: "Save Changes" }));

    await waitFor(() => expect(calls("PUT", "/api/v1/sdn/zones/dmz")).toHaveLength(1));
    expect(sentBody("PUT", "/api/v1/sdn/zones/dmz")).toEqual({
      offset: 0,
      port_classes: [],
      internet_ingress: false,
      isolate_from: [],
      allow_to: [],
      services: [],
      isolate: false,
      oob: false,
      lifecycle_role: "",
    });
  });

  it("overrides a built-in zone's policy without its offset or port classes", async () => {
    on("GET", "/api/v1/sdn/zones", { body: { zones: [fabric, lab] } });
    on("PUT", "/api/v1/sdn/zones/fabric", { status: 409, raw: "" });

    render(<ZonesPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Override (Edit) fabric" }));

    expect(dialog().getByText("Override Built-in Zone: fabric")).toBeTruthy();
    expect(dialog().getByText(/Your policy replaces the built-in defaults/)).toBeTruthy();
    expect(dialog().queryByLabelText("Offset (9-99)")).toBeNull();
    expect(dialog().queryByRole("switch", { name: "gateway" })).toBeNull();
    // The zone is not offered as its own isolate_from target.
    const isolateFrom = dialog().getByLabelText("Select zone to exclude...");
    expect(within(isolateFrom).queryByRole("option", { name: "fabric" })).toBeNull();
    fireEvent.click(dialog().getByRole("button", { name: "Save Changes" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Failed to update zone", description: "HTTP 409" })
      )
    );
    expect(dialog().getByText("Override Built-in Zone: fabric")).toBeTruthy();
  });

  it("closes the form on Cancel without sending anything", async () => {
    on("GET", "/api/v1/sdn/zones", { body: { zones: [lab] } });

    render(<ZonesPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Edit lab/1" }));
    fireEvent.click(dialog().getByRole("button", { name: "Cancel" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("deletes a zone by its encoded name and reloads the list", async () => {
    on("GET", "/api/v1/sdn/zones", { body: { zones: [lab] } }, { body: { zones: [] } });
    on("DELETE", "/api/v1/sdn/zones/lab%2F1", { status: 204, raw: "" });

    render(<ZonesPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete lab/1" }));

    expect(dialog().getByText("Delete Zone: lab/1")).toBeTruthy();
    expect(dialog().getByText(/removed at the next daemon restart/)).toBeTruthy();
    fireEvent.click(dialog().getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(calls("DELETE", "/api/v1/sdn/zones/lab%2F1")).toHaveLength(1);
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Zone deleted" }));
    await waitFor(() => expect(stat("Total")).toBe("0"));
  });

  it("shows a refused delete in the dialog and clears it on Cancel", async () => {
    on("GET", "/api/v1/sdn/zones", { body: { zones: [fabric] } });
    on(
      "DELETE",
      "/api/v1/sdn/zones/fabric",
      { status: 400, body: { error: "fabric cannot be removed" } },
      { status: 500, raw: "not json" }
    );

    render(<ZonesPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete fabric" }));

    expect(dialog().getByText(/Deleting a built-in zone omits it/)).toBeTruthy();
    fireEvent.click(dialog().getByRole("button", { name: "Delete" }));

    expect(await dialog().findByText("Delete Failed")).toBeTruthy();
    expect(dialog().getByText("fabric cannot be removed")).toBeTruthy();
    expect(toast).not.toHaveBeenCalled();

    fireEvent.click(dialog().getByRole("button", { name: "Delete" }));
    expect(await dialog().findByText("HTTP 500")).toBeTruthy();

    fireEvent.click(dialog().getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    fireEvent.click(screen.getByRole("button", { name: "Delete fabric" }));
    expect(dialog().queryByText("Delete Failed")).toBeNull();
  });
});
