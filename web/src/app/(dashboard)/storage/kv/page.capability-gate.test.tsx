import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the KV store page lists, puts and deletes through
// useQuicBaaSKV (network boundary, mocked here) and gates the list and every
// control on the server's capabilities.

const { kv, toast, capability } = vi.hoisted(() => ({
  kv: { list: vi.fn(), put: vi.fn(), delete: vi.fn() },
  toast: vi.fn(),
  capability: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useQuicBaaSKV: () => kv,
  useToast: () => ({ toast }),
}));

// #2033 item 5: Gated and the page read the server's capabilities through this hook.
vi.mock("@/hooks/use-capabilities", () => ({ useCapabilities: () => ({ loading: false, error: undefined, capability }) }));

// The Radix menu's portal does not settle in jsdom, so row menus render inline
// and keep the gate's disabled and title.
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

import KVStorePage from "./page";

const LIST_OP = "GET /api/v1/quicbaas/kv";
const PUT_OP = "POST /api/v1/quicbaas/kv";
const DELETE_OP = "DELETE /api/v1/quicbaas/kv/{key}";
const REASON = "blocked: integration";

const entry = { key: "config/app", value: btoa("hello"), version: 1, createdAt: Date.now(), modifiedAt: Date.now() };

function offExcept(off: string[]) {
  capability.mockImplementation((op: string) => (off.includes(op) ? { enabled: false, reason: REASON } : { enabled: true }));
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole("button", { name }) as HTMLButtonElement;
}

function expectWithheld(el: HTMLElement, op?: string) {
  expect((el as HTMLButtonElement).disabled).toBe(true);
  expect(el.getAttribute("title")).toBe(REASON);
  if (op) {
    expect(el.getAttribute("data-capability-op")).toBe(op);
    expect(el.getAttribute("data-capability-enabled")).toBe("false");
  }
}

beforeEach(() => {
  for (const fn of Object.values(kv)) fn.mockReset();
  kv.list.mockResolvedValue({ data: { kvs: [] } });
  kv.put.mockResolvedValue({ data: {} });
  kv.delete.mockResolvedValue({ data: {} });
  toast.mockReset();
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
});

afterEach(() => {
  cleanup();
});

describe("KVStorePage capability gate", () => {
  it("shows the not-enabled card with the server's reason and does not list when GET /api/v1/quicbaas/kv is not offered", async () => {
    offExcept([LIST_OP]);
    render(<KVStorePage />);

    const card = await screen.findByTestId("kv-not-enabled");
    expect(card.textContent).toContain(REASON);
    expect(kv.list).not.toHaveBeenCalled();
    expectWithheld(button("Refresh"), LIST_OP);
  });

  it("withholds Add Entry, Save Entry and Add your first entry when POST /api/v1/quicbaas/kv is not offered", async () => {
    const { rerender } = render(<KVStorePage />);
    await screen.findByRole("button", { name: "Add your first entry" });

    // Open the dialog while the server offers the op, then the server withdraws it.
    fireEvent.click(button("Add Entry"));
    await screen.findByRole("button", { name: "Save Entry" });
    offExcept([PUT_OP]);
    rerender(<KVStorePage />);

    expectWithheld(button("Save Entry"), PUT_OP);
    fireEvent.click(button("Save Entry"));
    expect(kv.put).not.toHaveBeenCalled();

    fireEvent.keyDown(document.activeElement ?? document.body, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("button", { name: "Save Entry" })).toBeNull());

    expectWithheld(button("Add Entry"), PUT_OP);
    const first = button("Add your first entry");
    expectWithheld(first, PUT_OP);
    fireEvent.click(first);
    expect(screen.queryByRole("button", { name: "Save Entry" })).toBeNull();
  });

  it("withholds the row Edit and Delete and the bulk delete when their ops are not offered", async () => {
    kv.list.mockResolvedValue({ data: { kvs: [entry] } });
    offExcept([PUT_OP, DELETE_OP]);
    render(<KVStorePage />);
    await screen.findByText("config/app");

    const row = screen.getByText("config/app").closest("tr") as HTMLElement;
    const edit = within(row).getByRole("menuitem", { name: /Edit/ });
    const del = within(row).getByRole("menuitem", { name: /Delete/ });
    expectWithheld(edit);
    expectWithheld(del);
    fireEvent.click(del);
    expect(kv.delete).not.toHaveBeenCalled();

    fireEvent.click(within(row).getByRole("checkbox", { name: "Select row" }));
    const bulk = await screen.findByRole("button", { name: /Delete selected/ });
    expectWithheld(bulk);
    fireEvent.click(bulk);
    expect(kv.delete).not.toHaveBeenCalled();
  });

  it("leaves every control enabled when the server offers the KV ops", async () => {
    kv.list.mockResolvedValue({ data: { kvs: [entry] } });
    render(<KVStorePage />);
    await screen.findByText("config/app");

    expect(capability).toHaveBeenCalledWith(LIST_OP);
    expect(capability).toHaveBeenCalledWith(PUT_OP);
    expect(capability).toHaveBeenCalledWith(DELETE_OP);
    expect(screen.queryByTestId("kv-not-enabled")).toBeNull();

    for (const name of ["Refresh", "Add Entry"]) {
      const el = button(name);
      expect(el.disabled).toBe(false);
      expect(el.getAttribute("data-capability-enabled")).toBe("true");
    }
    const row = screen.getByText("config/app").closest("tr") as HTMLElement;
    expect((within(row).getByRole("menuitem", { name: /Edit/ }) as HTMLButtonElement).disabled).toBe(false);
    expect((within(row).getByRole("menuitem", { name: /Delete/ }) as HTMLButtonElement).disabled).toBe(false);

    fireEvent.click(within(row).getByRole("checkbox", { name: "Select row" }));
    const bulk = await screen.findByRole("button", { name: /Delete selected/ });
    expect((bulk as HTMLButtonElement).disabled).toBe(false);
  });
});
