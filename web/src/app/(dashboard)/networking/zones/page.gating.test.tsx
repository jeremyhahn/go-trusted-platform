import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import { ToastProbe } from "@/test/control-plane-fetch";
import { useToast } from "@/hooks/use-toast";

import ZonesPage from "./page";

// In jsdom, closing the Radix row menu while the page opens a dialog from
// its item spends close to a minute settling focus, so the row actions render
// as plain buttons. Each one still calls the page's own action for the row and
// carries the item's disabled and title.
vi.mock("@/components/ui/data-table-row-actions", () => ({
  DataTableRowActions: ({
    row,
    actions = [],
  }: {
    row: unknown;
    actions?: {
      label: string;
      onClick: (row: unknown) => void;
      disabled?: boolean;
      title?: string;
    }[];
  }) => (
    <div onClick={(e) => e.stopPropagation()}>
      {actions.map((action) => (
        <button
          key={action.label}
          type="button"
          disabled={action.disabled}
          title={action.title}
          onClick={() => action.onClick(row)}
        >
          {action.label}
        </button>
      ))}
    </div>
  ),
}));

const caps = vi.hoisted(() => ({ capability: vi.fn() }));

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: false, error: undefined, capability: caps.capability }),
}));

// #2065: every control on the zones page is gated on the server's op.
const LIST_OP = "GET /api/v1/sdn/zones";
const CREATE_OP = "POST /api/v1/sdn/zones";
const UPDATE_OP = "PUT /api/v1/sdn/zones/{name}";
const DELETE_OP = "DELETE /api/v1/sdn/zones/{name}";

/** Offers every op but those in off, which answer disabled with their reason. */
function offer(off: Record<string, string> = {}) {
  caps.capability.mockImplementation((op: string) =>
    op in off ? { enabled: false, reason: off[op] } : { enabled: true }
  );
}

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

/** The GET /api/v1/sdn/zones answer: a built-in and an owner zone. */
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

describe("ZonesPage capability gating (#2065)", () => {
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
      "GET /api/v1/sdn/zones": twoZones,
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

  async function noDialog(): Promise<void> {
    await waitFor(() => expect(document.querySelector('[role="dialog"]')).toBeNull());
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

  function mutations(): number {
    return (
      callsTo("POST", "/api/v1/sdn/zones").length +
      callsTo("PUT", "/api/v1/sdn/zones/lab").length +
      callsTo("DELETE", "/api/v1/sdn/zones/lab").length
    );
  }

  beforeEach(() => {
    fetchMock.mockReset();
    globalFetch.mockClear();
    vi.stubGlobal("fetch", globalFetch);
    caps.capability.mockReset();
    offer();
  });

  afterEach(() => {
    act(() => dismissToasts?.());
    vi.unstubAllGlobals();
    cleanup();
  });

  it("withholds Create Zone with the server reason when create is not offered", async () => {
    offer({ [CREATE_OP]: "not-configured: sdn" });
    routes();
    renderPage();
    await screen.findByText("lab");

    const create = buttonIn(document.body, "Create Zone") as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    expect(create.getAttribute("title")).toBe("not-configured: sdn");
    expect(create.getAttribute("data-capability-op")).toBe(CREATE_OP);
    expect(create.getAttribute("data-capability-enabled")).toBe("false");

    fireEvent.click(create);
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(callsTo("POST", "/api/v1/sdn/zones")).toHaveLength(0);
  });

  it("withholds the Edit and Delete row actions when update and delete are not offered", async () => {
    offer({
      [UPDATE_OP]: "not-configured: sdn update",
      [DELETE_OP]: "not-configured: sdn delete",
    });
    routes();
    renderPage();
    const row = await rowOf("lab");

    const edit = buttonIn(row, "Edit") as HTMLButtonElement;
    const del = buttonIn(row, "Delete") as HTMLButtonElement;
    expect(edit.disabled).toBe(true);
    expect(edit.getAttribute("title")).toBe("not-configured: sdn update");
    expect(del.disabled).toBe(true);
    expect(del.getAttribute("title")).toBe("not-configured: sdn delete");

    fireEvent.click(edit);
    fireEvent.click(del);
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(mutations()).toBe(0);
  });

  it("does not list the zones when the list is not offered", async () => {
    offer({ [LIST_OP]: "not-configured: sdn" });
    routes();
    renderPage();

    expect(await screen.findByText("Zones unavailable")).toBeTruthy();
    expect(screen.getByText("not-configured: sdn")).toBeTruthy();
    expect(callsTo("GET", "/api/v1/sdn/zones")).toHaveLength(0);

    const refresh = document.querySelector(
      `button[data-capability-op="${LIST_OP}"]`
    ) as HTMLButtonElement | null;
    expect(refresh).toBeTruthy();
    expect(refresh?.disabled).toBe(true);
  });

  it("gates the dialog submit and the delete confirm on their ops", async () => {
    routes();
    renderPage();
    await screen.findByText("lab");

    fireEvent.click(buttonIn(document.body, "Create Zone"));
    let dialog = await findDialog();
    const submit = buttonIn(dialog, "Create Zone");
    expect(submit.getAttribute("data-capability-op")).toBe(CREATE_OP);
    expect(submit.getAttribute("data-capability-enabled")).toBe("true");
    fireEvent.click(buttonIn(dialog, "Cancel"));
    await noDialog();

    fireEvent.click(buttonIn(await rowOf("lab"), "Edit"));
    dialog = await findDialog();
    const save = buttonIn(dialog, "Save Changes");
    expect(save.getAttribute("data-capability-op")).toBe(UPDATE_OP);
    expect(save.getAttribute("data-capability-enabled")).toBe("true");
    fireEvent.click(buttonIn(dialog, "Cancel"));
    await noDialog();

    fireEvent.click(buttonIn(await rowOf("lab"), "Delete"));
    dialog = await findDialog();
    const confirm = buttonIn(dialog, "Delete");
    expect(confirm.getAttribute("data-capability-op")).toBe(DELETE_OP);
    expect(confirm.getAttribute("data-capability-enabled")).toBe("true");
    expect(mutations()).toBe(0);
  });

  it("asks the gate for all four zone ops", async () => {
    routes();
    renderPage();
    await screen.findByText("lab");

    for (const op of [LIST_OP, CREATE_OP, UPDATE_OP, DELETE_OP]) {
      expect(caps.capability).toHaveBeenCalledWith(op);
    }
  });
});
