import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the vector database page reads and changes collections through
// useQuicBaaSVector (network boundary, mocked here) and gates the namespace
// list, Refresh, Create Collection, Search and Delete on the server's
// capabilities.

const { vector, toast, capability } = vi.hoisted(() => ({
  vector: { listNamespaces: vi.fn(), createNamespace: vi.fn(), deleteNamespace: vi.fn(), search: vi.fn() },
  toast: vi.fn(),
  capability: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useQuicBaaSVector: () => vector,
  useToast: () => ({ toast }),
}));

// #2033 item 5: the page and Gated read the server's capabilities through this hook.
vi.mock("@/hooks/use-capabilities", () => ({ useCapabilities: () => ({ loading: false, error: undefined, capability }) }));

// The Radix menu's portal does not settle in jsdom, so row menus render inline;
// the items keep their disabled state and title.
vi.mock("@/components/ui/dropdown-menu", async (importOriginal) => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Item = ({
    children,
    onClick,
    disabled,
    title,
  }: {
    children?: React.ReactNode;
    onClick?: () => void;
    disabled?: boolean;
    title?: string;
  }) => (
    <button type="button" role="menuitem" onClick={onClick} disabled={disabled} title={title}>
      {children}
    </button>
  );
  return {
    ...(await importOriginal<typeof import("@/components/ui/dropdown-menu")>()),
    DropdownMenu: Pass,
    DropdownMenuTrigger: Pass,
    DropdownMenuContent: Pass,
    DropdownMenuItem: Item,
  };
});

// The Radix select needs pointer capture jsdom lacks, so it renders as a
// native select over the same items.
vi.mock("@/components/ui/select", () => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Select = ({ value, onValueChange, children }: { value?: string; onValueChange?: (v: string) => void; children?: React.ReactNode }) => (
    <select value={value} onChange={(e) => onValueChange?.(e.target.value)}>
      <option value="">none</option>
      {children}
    </select>
  );
  const Item = ({ value, children }: { value: string; children?: React.ReactNode }) => <option value={value}>{children}</option>;
  return { Select, SelectTrigger: () => null, SelectValue: () => null, SelectContent: Pass, SelectItem: Item };
});

// The dialogs render inline so their submit buttons can be checked while the
// gated triggers cannot open them; the trigger hands its props to its child.
vi.mock("@/components/ui/dialog", () => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Trigger = ({ children, asChild: _asChild, ...props }: { children: React.ReactElement; asChild?: boolean }) =>
    React.cloneElement(children, props);
  return {
    Dialog: Pass,
    DialogTrigger: Trigger,
    DialogContent: Pass,
    DialogHeader: Pass,
    DialogTitle: Pass,
    DialogDescription: Pass,
  };
});

import VectorDatabasePage from "./page";

const LIST_OP = "GET /api/v1/quicbaas/vector/namespaces";
const CREATE_OP = "POST /api/v1/quicbaas/vector/namespaces";
const SEARCH_OP = "POST /api/v1/quicbaas/vector/search";
const DELETE_OP = "DELETE /api/v1/quicbaas/vector/namespaces/{name}";

const namespaces = [
  { name: "docs", dimension: 384, metric: "COSINE", vectorCount: 1500, createdAt: 1_700_000_000 },
  { name: "images", dimension: 512, metric: "EUCLIDEAN", vectorCount: 0, createdAt: 1_700_000_000 },
];

function darken(op: string, reason: string) {
  capability.mockImplementation((asked: string) => (asked === op ? { enabled: false, reason } : { enabled: true }));
}

function rowFor(name: string): HTMLElement {
  const row = screen.getByText(name).closest("tr");
  if (!row) throw new Error(`no table row for ${name}`);
  return row;
}

function expectWithheld(el: HTMLElement, op: string, reason: string) {
  expect((el as HTMLButtonElement).disabled).toBe(true);
  expect(el.getAttribute("title")).toBe(reason);
  expect(el.getAttribute("data-capability-op")).toBe(op);
  expect(el.getAttribute("data-capability-enabled")).toBe("false");
}

beforeEach(() => {
  for (const fn of Object.values(vector)) fn.mockReset();
  vector.listNamespaces.mockResolvedValue({ data: { namespaces } });
  vector.createNamespace.mockResolvedValue({ data: { name: "new" } });
  vector.deleteNamespace.mockResolvedValue({ data: {} });
  vector.search.mockResolvedValue({ data: { results: [] } });
  toast.mockReset();
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("VectorDatabasePage capability gate", () => {
  it("shows the not-enabled card with the server's reason and does not list when GET /api/v1/quicbaas/vector/namespaces is not offered", async () => {
    darken(LIST_OP, "blocked: integration");
    render(<VectorDatabasePage />);

    const card = await screen.findByTestId("vector-not-enabled");
    expect(card.textContent).toContain("blocked: integration");
    expect(card.textContent).toContain("The vector database is not enabled on this server");
    expectWithheld(screen.getByRole("button", { name: /Refresh/ }), LIST_OP, "blocked: integration");
    expect(vector.listNamespaces).not.toHaveBeenCalled();
  });

  it("withholds Create Collection, the dialog's Create and Create your first collection when POST /api/v1/quicbaas/vector/namespaces is not offered", async () => {
    vector.listNamespaces.mockResolvedValue({ data: {} });
    darken(CREATE_OP, "blocked: integration");
    render(<VectorDatabasePage />);
    await screen.findByText("No collections found");

    const creates = screen.getAllByRole("button", { name: /^Create Collection$/ });
    expect(creates).toHaveLength(2);
    for (const button of creates) expectWithheld(button, CREATE_OP, "blocked: integration");
    expectWithheld(screen.getByRole("button", { name: /Create your first collection/ }), CREATE_OP, "blocked: integration");

    fireEvent.change(screen.getByLabelText("Collection Name"), { target: { value: "embeddings" } });
    fireEvent.click(creates[1]);
    expect(vector.createNamespace).not.toHaveBeenCalled();
  });

  it("withholds Search Vectors, the row Search item and the dialog's Search when POST /api/v1/quicbaas/vector/search is not offered", async () => {
    darken(SEARCH_OP, "not offered by this server");
    render(<VectorDatabasePage />);
    await screen.findByText("docs");

    expectWithheld(screen.getByRole("button", { name: /^Search Vectors$/ }), SEARCH_OP, "not offered by this server");
    const rowSearch = within(rowFor("docs")).getByRole("menuitem", { name: /Search Vectors/ }) as HTMLButtonElement;
    expect(rowSearch.disabled).toBe(true);
    expect(rowSearch.getAttribute("title")).toBe("not offered by this server");
    const submit = screen.getByRole("button", { name: "Search" });
    expectWithheld(submit, SEARCH_OP, "not offered by this server");

    fireEvent.change(screen.getByDisplayValue("none"), { target: { value: "docs" } });
    fireEvent.change(screen.getByLabelText("Query Vector (JSON array)"), { target: { value: "[1]" } });
    fireEvent.click(rowSearch);
    fireEvent.click(submit);
    expect(vector.search).not.toHaveBeenCalled();
  });

  it("withholds the row Delete and the bulk delete when DELETE /api/v1/quicbaas/vector/namespaces/{name} is not offered", async () => {
    vi.stubGlobal("confirm", vi.fn(() => true));
    darken(DELETE_OP, "not offered by this server");
    render(<VectorDatabasePage />);
    await screen.findByText("docs");

    const rowDelete = within(rowFor("docs")).getByRole("menuitem", { name: /Delete/ }) as HTMLButtonElement;
    expect(rowDelete.disabled).toBe(true);
    expect(rowDelete.getAttribute("title")).toBe("not offered by this server");
    fireEvent.click(rowDelete);

    fireEvent.click(within(rowFor("images")).getByRole("checkbox", { name: "Select row" }));
    const bulk = screen.getByRole("button", { name: "Delete selected (1)" }) as HTMLButtonElement;
    expect(bulk.disabled).toBe(true);
    expect(bulk.getAttribute("title")).toBe("not offered by this server");
    fireEvent.click(bulk);

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(vector.deleteNamespace).not.toHaveBeenCalled();
  });

  it("leaves every control enabled when the server offers the vector ops", async () => {
    render(<VectorDatabasePage />);
    await waitFor(() => expect(vector.listNamespaces).toHaveBeenCalled());
    await screen.findByText("docs");

    for (const op of [LIST_OP, CREATE_OP, SEARCH_OP, DELETE_OP]) expect(capability).toHaveBeenCalledWith(op);
    expect(screen.queryByTestId("vector-not-enabled")).toBeNull();
    const gated = [
      screen.getByRole("button", { name: /Refresh/ }),
      screen.getByRole("button", { name: /^Search Vectors$/ }),
      screen.getByRole("button", { name: "Search" }),
      ...screen.getAllByRole("button", { name: /^Create Collection$/ }),
    ];
    for (const button of gated) expect(button.getAttribute("data-capability-enabled")).toBe("true");
    for (const item of within(rowFor("docs")).getAllByRole("menuitem")) {
      expect((item as HTMLButtonElement).disabled).toBe(false);
    }
  });
});
