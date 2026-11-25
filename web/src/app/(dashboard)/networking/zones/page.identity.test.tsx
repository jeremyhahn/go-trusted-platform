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

// #2065: the page offers only the zone changes the server accepts. The
// required built-ins (pkg/sdn/zone/defaults.go requiredBuiltins) are never
// omitted, and an owner-defined zone needs an offset 9-99 and at least one
// port class (pkg/sdn/zone/validate.go validateIdentity).

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

/** The GET /api/v1/sdn/zones answer: a required built-in, a built-in and an owner zone. */
function threeZones(): Response {
  return ok({
    zones: [
      {
        name: "fabric",
        offset: 1,
        port_classes: ["gateway", "hypervisor"],
        created_at: "2026-11-01T00:00:00Z",
        updated_at: "2026-11-01T00:00:00Z",
      },
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
    count: 3,
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

const HINT = "An owner-defined zone needs an offset 9-99 and at least one port class.";

describe("ZonesPage zone identity checks (#2065)", () => {
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

  /** Answers "METHOD /path" keys; the zone list by default, 404 otherwise. */
  function routes(answers: Record<string, () => Response> = {}) {
    const table: Record<string, () => Response> = {
      "GET /api/v1/sdn/zones": threeZones,
      ...answers,
    };
    fetchMock.mockImplementation((input, init) => {
      const url = new URL(String(input));
      const answer = table[`${init?.method ?? "GET"} ${url.pathname}`];
      return Promise.resolve(answer ? answer() : failure(404, `no route ${url.pathname}`));
    });
  }

  async function findDialog(): Promise<HTMLElement> {
    return waitFor(() => {
      const dialog = document.querySelector('[role="dialog"]');
      expect(dialog).toBeTruthy();
      return dialog as HTMLElement;
    });
  }

  function findButton(container: HTMLElement, label: string): HTMLElement | undefined {
    return Array.from(container.querySelectorAll("button")).find(
      (el) => el.textContent?.trim() === label
    );
  }

  function buttonIn(container: HTMLElement, label: string): HTMLElement {
    const button = findButton(container, label);
    expect(button).toBeTruthy();
    return button as HTMLElement;
  }

  /** The table row of zone name. */
  async function rowOf(name: string): Promise<HTMLElement> {
    const row = (await screen.findByText(name)).closest("tr");
    expect(row).toBeTruthy();
    return row as HTMLElement;
  }

  async function openCreateDialog(): Promise<HTMLElement> {
    await screen.findByText("lab");
    fireEvent.click(buttonIn(document.body, "Create Zone"));
    const dialog = await findDialog();
    fireEvent.change(within(dialog).getByLabelText("Name *"), { target: { value: "edge" } });
    return dialog;
  }

  function isDisabled(button: HTMLElement): boolean {
    return (button as HTMLButtonElement).disabled;
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

  it("offers no Delete for a required built-in zone", async () => {
    routes();
    renderPage();

    const fabric = await rowOf("fabric");
    expect(findButton(fabric, "Override (Edit)")).toBeTruthy();
    expect(findButton(fabric, "Delete")).toBeUndefined();
    expect(findButton(await rowOf("management"), "Delete")).toBeTruthy();
    expect(findButton(await rowOf("lab"), "Delete")).toBeTruthy();
    expect(globalFetch).not.toHaveBeenCalled();
  });

  it("keeps Create Zone disabled while the new zone has no port class", async () => {
    routes({ "POST /api/v1/sdn/zones": () => ok({ name: "edge", offset: 9 }) });
    renderPage();

    const dialog = await openCreateDialog();
    fireEvent.click(within(dialog).getByLabelText("hypervisor"));
    expect(isDisabled(buttonIn(dialog, "Create Zone"))).toBe(true);
    expect(within(dialog).queryByText(HINT)).toBeTruthy();

    fireEvent.click(within(dialog).getByLabelText("gateway"));
    expect(isDisabled(buttonIn(dialog, "Create Zone"))).toBe(false);
    expect(within(dialog).queryByText(HINT)).toBeNull();

    await act(async () => {
      fireEvent.click(buttonIn(dialog, "Create Zone"));
    });
    await waitFor(() => expect(callsTo("POST", "/api/v1/sdn/zones")).toHaveLength(1));
    const body = JSON.parse(String(callsTo("POST", "/api/v1/sdn/zones")[0][1]?.body));
    expect(body.port_classes).toEqual(["gateway"]);
    expect(globalFetch).not.toHaveBeenCalled();
  });

  it("keeps Create Zone disabled while the offset is outside 9-99", async () => {
    routes();
    renderPage();

    const dialog = await openCreateDialog();
    const offset = within(dialog).getByLabelText("Offset (9-99)");
    for (const value of ["5", "100", ""]) {
      fireEvent.change(offset, { target: { value } });
      expect(isDisabled(buttonIn(dialog, "Create Zone"))).toBe(true);
      fireEvent.click(buttonIn(dialog, "Create Zone"));
      expect(callsTo("POST", "/api/v1/sdn/zones")).toHaveLength(0);
    }
    fireEvent.change(offset, { target: { value: "12" } });
    expect(isDisabled(buttonIn(dialog, "Create Zone"))).toBe(false);
    expect(callsTo("POST", "/api/v1/sdn/zones")).toHaveLength(0);
  });

  it("keeps Save Changes disabled when an owner zone's offset leaves 9-99", async () => {
    routes();
    renderPage();

    fireEvent.click(buttonIn(await rowOf("lab"), "Edit"));
    const dialog = await findDialog();
    fireEvent.change(within(dialog).getByLabelText("Offset (9-99)"), { target: { value: "5" } });
    expect(isDisabled(buttonIn(dialog, "Save Changes"))).toBe(true);
    fireEvent.click(buttonIn(dialog, "Save Changes"));
    expect(callsTo("PUT", "/api/v1/sdn/zones/lab")).toHaveLength(0);
  });

  it("does not hold a built-in override to the owner checks", async () => {
    routes();
    renderPage();

    fireEvent.click(buttonIn(await rowOf("management"), "Override (Edit)"));
    const dialog = await findDialog();
    expect(isDisabled(buttonIn(dialog, "Save Changes"))).toBe(false);
  });
});
