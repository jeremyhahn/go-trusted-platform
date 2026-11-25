import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import { ToastProbe } from "@/test/control-plane-fetch";
import { useToast } from "@/hooks/use-toast";

import ZonesPage from "./page";

// In jsdom, closing the Radix row menu while the page opens a dialog from
// its item spends close to a minute settling focus, so the row actions render
// as plain buttons. Each one still calls the page's own action for the row.
vi.mock("@/components/ui/data-table-row-actions", () => ({
  DataTableRowActions: ({
    row,
    actions = [],
  }: {
    row: unknown;
    actions?: { label: string; onClick: (row: unknown) => void }[];
  }) => (
    <div onClick={(e) => e.stopPropagation()}>
      {actions.map((action) => (
        <button key={action.label} type="button" onClick={() => action.onClick(row)}>
          {action.label}
        </button>
      ))}
    </div>
  ),
}));

// #2065: the page gates its controls on the server's capabilities; these cases have every op offered.
vi.mock("@/hooks/use-capabilities", () => ({ useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }) }));

// #2065: the page drives the network zones through client.sdn on the REST
// zone shape (pkg/webservice/v1/rest/sdn/zones.go). These tests stub the
// client's fetch with the {code,error,success,payload} envelopes the
// webservice writes; the global fetch refuses, so a hand-written call fails.

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function ok(payload: unknown): Response {
  return jsonResponse(200, { code: 200, error: "", success: true, payload });
}

function failure(status: number, error: string): Response {
  return jsonResponse(status, { code: status, error, success: false });
}

/** The GET /api/v1/sdn/zones answer: one built-in zone and one custom zone. */
function twoZones(): Response {
  return ok({
    zones: [
      {
        name: "management",
        offset: 2,
        isolate: true,
        created_at: "2026-11-01T00:00:00Z",
        updated_at: "2026-11-01T00:00:00Z",
      },
      {
        name: "lab",
        offset: 9,
        port_classes: ["hypervisor"],
        created_at: "2026-11-01T00:00:00Z",
        updated_at: "2026-11-01T00:00:00Z",
      },
    ],
    count: 2,
    timestamp: "2026-11-01T00:00:00Z",
  });
}

// The toast store outlives a render; ToastDismiss hands the tests its
// dismiss so each test starts with no toast left from the one before.
let dismissToasts: (() => void) | undefined;

function ToastDismiss() {
  const { dismiss, toasts } = useToast();
  dismissToasts = () => toasts.forEach((t) => dismiss(t.id));
  return null;
}

describe("ZonesPage", () => {
  const fetchMock = vi.fn<typeof fetch>();
  const globalFetch = vi.fn(() => Promise.reject(new Error("global fetch")));

  function renderPage() {
    const client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: fetchMock,
      retry: { maxRetries: 0 },
    });
    return render(
      <PlatformProvider client={client}>
        <ZonesPage />
        <ToastProbe />
        <ToastDismiss />
      </PlatformProvider>
    );
  }

  /** The calls fetch saw for one method and path. */
  function callsTo(method: string, path: string) {
    return fetchMock.mock.calls.filter(([input, init]) => {
      return (init?.method ?? "GET") === method && new URL(String(input)).pathname === path;
    });
  }

  beforeEach(() => {
    fetchMock.mockReset();
    globalFetch.mockClear();
    vi.stubGlobal("fetch", globalFetch);
  });

  afterEach(() => {
    act(() => dismissToasts?.());
    vi.unstubAllGlobals();
    cleanup();
  });

  it("lists the zones through client.sdn", async () => {
    fetchMock.mockImplementation((input, init) => {
      const url = new URL(String(input));
      if ((init?.method ?? "GET") === "GET" && url.pathname === "/api/v1/sdn/zones") {
        return Promise.resolve(twoZones());
      }
      return Promise.resolve(failure(404, `no route ${url.pathname}`));
    });

    renderPage();

    expect(await screen.findByText("lab")).toBeTruthy();
    expect(screen.getByText("management")).toBeTruthy();
    expect(callsTo("GET", "/api/v1/sdn/zones")).toHaveLength(1);
    expect(globalFetch).not.toHaveBeenCalled();
  });

  it("shows the server error when the list fails", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(failure(500, "list zones: boom")));

    renderPage();

    expect(await screen.findByText("Error Loading Zones")).toBeTruthy();
    expect(screen.getByText(/list zones: boom/)).toBeTruthy();
    expect(globalFetch).not.toHaveBeenCalled();
  });

  describe("ZonesPage mutations", () => {
    /** Answers "METHOD /path" keys; the zone list by default, 404 otherwise. */
    function routes(answers: Record<string, () => Response>) {
      const table: Record<string, () => Response> = {
        "GET /api/v1/sdn/zones": twoZones,
        ...answers,
      };
      fetchMock.mockImplementation((input, init) => {
        const url = new URL(String(input));
        const answer = table[`${init?.method ?? "GET"} ${url.pathname}`];
        return Promise.resolve(answer ? answer() : failure(404, `no route ${url.pathname}`));
      });
    }

    /** The JSON body of the single call to method and path. */
    function bodyOf(method: string, path: string): Record<string, unknown> {
      const calls = callsTo(method, path);
      expect(calls).toHaveLength(1);
      return JSON.parse(String(calls[0][1]?.body));
    }

    // A role query over the whole page walks its accessibility tree for
    // seconds per retry, so the dialog, its buttons and the menu items are
    // found through the DOM.
    async function findDialog(): Promise<HTMLElement> {
      return waitFor(() => {
        const dialog = document.querySelector('[role="dialog"]');
        expect(dialog).toBeTruthy();
        return dialog as HTMLElement;
      });
    }

    function buttonIn(container: HTMLElement, label: string): HTMLElement {
      const button = Array.from(container.querySelectorAll("button")).find(
        (el) => el.textContent?.trim() === label
      );
      expect(button).toBeTruthy();
      return button as HTMLElement;
    }

    /** Picks action from the row actions of zone name. */
    async function pickRowAction(name: string, action: string) {
      const row = (await screen.findByText(name)).closest("tr");
      expect(row).toBeTruthy();
      fireEvent.click(buttonIn(row as HTMLElement, action));
    }

    async function openCreateDialog(): Promise<HTMLElement> {
      await screen.findByText("lab");
      fireEvent.click(buttonIn(document.body, "Create Zone"));
      const dialog = await findDialog();
      fireEvent.change(within(dialog).getByLabelText("Name *"), { target: { value: "edge" } });
      return dialog;
    }

    const newZoneBody = {
      offset: 9,
      port_classes: ["hypervisor"],
      internet_ingress: false,
      isolate_from: [],
      allow_to: [],
      services: [],
      isolate: true,
      oob: false,
      lifecycle_role: "",
      name: "edge",
    };

    it("creates a zone from the dialog and refreshes the list", async () => {
      routes({ "POST /api/v1/sdn/zones": () => ok({ name: "edge", offset: 9 }) });
      renderPage();

      const dialog = await openCreateDialog();
      await act(async () => {
        fireEvent.click(buttonIn(dialog, "Create Zone"));
      });

      expect(await screen.findByText(/^Zone created/)).toBeTruthy();
      expect(bodyOf("POST", "/api/v1/sdn/zones")).toEqual(newZoneBody);
      await waitFor(() => expect(callsTo("GET", "/api/v1/sdn/zones")).toHaveLength(2));
      expect(globalFetch).not.toHaveBeenCalled();
    });

    it("shows the refusal and keeps the dialog open when create fails", async () => {
      routes({ "POST /api/v1/sdn/zones": () => failure(400, "zone edge: offset 9 in use") });
      renderPage();

      const dialog = await openCreateDialog();
      await act(async () => {
        fireEvent.click(buttonIn(dialog, "Create Zone"));
      });

      const toast = await screen.findByText("Failed to create zone: zone edge: offset 9 in use");
      expect(toast.getAttribute("data-variant")).toBe("destructive");
      expect(screen.queryByText(/^Zone created/)).toBeNull();
      expect(document.querySelector('[role="dialog"]')).toBeTruthy();
      expect(callsTo("POST", "/api/v1/sdn/zones")).toHaveLength(1);
      expect(callsTo("GET", "/api/v1/sdn/zones")).toHaveLength(1);
      expect(globalFetch).not.toHaveBeenCalled();
    });

    async function editLabOffset() {
      await pickRowAction("lab", "Edit");
      const dialog = await findDialog();
      fireEvent.change(within(dialog).getByLabelText("Offset (9-99)"), { target: { value: "12" } });
      await act(async () => {
        fireEvent.click(buttonIn(dialog, "Save Changes"));
      });
    }

    it("updates a zone from the dialog without a body name and refreshes the list", async () => {
      routes({ "PUT /api/v1/sdn/zones/lab": () => ok({ name: "lab", offset: 12 }) });
      renderPage();

      await editLabOffset();

      expect(await screen.findByText(/^Zone updated/)).toBeTruthy();
      const body = bodyOf("PUT", "/api/v1/sdn/zones/lab");
      expect(body.offset).toBe(12);
      expect(body.port_classes).toEqual(["hypervisor"]);
      expect(body).not.toHaveProperty("name");
      await waitFor(() => expect(callsTo("GET", "/api/v1/sdn/zones")).toHaveLength(2));
      expect(globalFetch).not.toHaveBeenCalled();
    });

    it("shows the refusal when update fails", async () => {
      routes({ "PUT /api/v1/sdn/zones/lab": () => failure(400, "zone lab: offset 12 in use") });
      renderPage();

      await editLabOffset();

      const toast = await screen.findByText("Failed to update zone: zone lab: offset 12 in use");
      expect(toast.getAttribute("data-variant")).toBe("destructive");
      expect(screen.queryByText(/^Zone updated/)).toBeNull();
      expect(callsTo("PUT", "/api/v1/sdn/zones/lab")).toHaveLength(1);
      expect(callsTo("GET", "/api/v1/sdn/zones")).toHaveLength(1);
      expect(globalFetch).not.toHaveBeenCalled();
    });

    async function deleteLab() {
      await pickRowAction("lab", "Delete");
      const dialog = await findDialog();
      await act(async () => {
        fireEvent.click(buttonIn(dialog, "Delete"));
      });
    }

    it("deletes a zone from the confirm dialog and refreshes the list", async () => {
      routes({ "DELETE /api/v1/sdn/zones/lab": () => ok({ name: "lab" }) });
      renderPage();

      await deleteLab();

      expect(await screen.findByText(/^Zone deleted/)).toBeTruthy();
      expect(callsTo("DELETE", "/api/v1/sdn/zones/lab")).toHaveLength(1);
      await waitFor(() => expect(callsTo("GET", "/api/v1/sdn/zones")).toHaveLength(2));
      expect(globalFetch).not.toHaveBeenCalled();
    });

    it("shows Delete Failed with no toast when delete fails", async () => {
      routes({ "DELETE /api/v1/sdn/zones/lab": () => failure(409, "zone lab: in use") });
      renderPage();

      await deleteLab();

      expect(await screen.findByText("Delete Failed")).toBeTruthy();
      expect(screen.getByText("zone lab: in use")).toBeTruthy();
      expect(screen.queryAllByTestId("toast")).toHaveLength(0);
      expect(callsTo("DELETE", "/api/v1/sdn/zones/lab")).toHaveLength(1);
      expect(callsTo("GET", "/api/v1/sdn/zones")).toHaveLength(1);
      expect(globalFetch).not.toHaveBeenCalled();
    });
  });
});
