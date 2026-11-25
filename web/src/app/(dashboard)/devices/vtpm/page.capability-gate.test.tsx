import * as React from "react";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the vTPM page lists, creates, seals and deletes bundles
// through useVTPM (network boundary, mocked here) and gates the list and
// every control on the server's capabilities.

const { vtpm, toast, capability, caps, push } = vi.hoisted(() => ({
  vtpm: {
    listBundles: vi.fn(),
    createBundle: vi.fn(),
    deleteBundle: vi.fn(),
    sealData: vi.fn(),
  },
  toast: vi.fn(),
  capability: vi.fn(),
  caps: { loading: false },
  push: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useVTPM: () => vtpm,
  useToast: () => ({ toast }),
}));

vi.mock("@/hooks/use-toast", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks/use-toast")>()),
  useToast: () => ({ toast }),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push, replace: vi.fn(), back: vi.fn(), refresh: vi.fn(), prefetch: vi.fn() }),
  usePathname: () => "/devices/vtpm",
  useSearchParams: () => new URLSearchParams(),
}));

// #2033 item 5: Gated and the page read the server's capabilities through this hook.
vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: caps.loading, error: undefined, capability }),
}));

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
    DropdownMenuLabel: Pass,
    DropdownMenuSeparator: () => null,
    DropdownMenuItem: Item,
  };
});

import VTPMPage from "./page";

const LIST_OP = "GET /api/v1/vtpm/bundles";
const CREATE_OP = "POST /api/v1/vtpm/bundles";
const DELETE_OP = "DELETE /api/v1/vtpm/bundles/{id}";
const SEAL_OP = "POST /api/v1/vtpm/bundles/{id}/seal";
const REASON = "blocked: integration";

const bundles = [{ id: "b-1", manifest: { hostname: "vm-alpha" }, createdAt: new Date().toISOString() }];

function offExcept(off: string[]) {
  capability.mockImplementation((op: string) => (off.includes(op) ? { enabled: false, reason: REASON } : { enabled: true }));
}

function expectWithheld(el: HTMLElement, op?: string) {
  expect((el as HTMLButtonElement).disabled).toBe(true);
  expect(el.getAttribute("title")).toBe(REASON);
  if (op) {
    expect(el.getAttribute("data-capability-op")).toBe(op);
    expect(el.getAttribute("data-capability-enabled")).toBe("false");
  }
}

function row(): HTMLElement {
  return screen.getAllByText("vm-alpha")[0].closest("tr") as HTMLElement;
}

beforeEach(() => {
  for (const fn of Object.values(vtpm)) fn.mockReset();
  vtpm.listBundles.mockResolvedValue({ data: { bundles } });
  toast.mockReset();
  push.mockReset();
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
  caps.loading = false;
});

afterEach(() => {
  cleanup();
});

describe("VTPMPage capability gate", () => {
  it("shows the not-enabled card with the server's reason and does not list when GET /api/v1/vtpm/bundles is not offered", async () => {
    offExcept([LIST_OP]);
    render(<VTPMPage />);

    const card = await screen.findByTestId("vtpm-not-enabled");
    expect(card.textContent).toContain(REASON);
    expect(vtpm.listBundles).not.toHaveBeenCalled();
  });

  it("shows the loading state and does not list while the capabilities load", async () => {
    caps.loading = true;
    capability.mockImplementation(() => ({ enabled: false, reason: "loading" }));
    render(<VTPMPage />);

    expect(screen.getByText("Loading vTPM instances...")).toBeTruthy();
    expect(screen.queryByTestId("vtpm-not-enabled")).toBeNull();
    expect(vtpm.listBundles).not.toHaveBeenCalled();
  });

  it("withholds Create vTPM when POST /api/v1/vtpm/bundles is not offered", async () => {
    offExcept([CREATE_OP]);
    render(<VTPMPage />);
    await screen.findAllByText("vm-alpha");

    expectWithheld(screen.getByRole("button", { name: /Create vTPM/ }), CREATE_OP);
  });

  it("withholds the row Delete when DELETE /api/v1/vtpm/bundles/{id} is not offered", async () => {
    offExcept([DELETE_OP]);
    render(<VTPMPage />);
    await screen.findAllByText("vm-alpha");

    const del = within(row()).getByRole("menuitem", { name: /Delete/ });
    expectWithheld(del);
    expect((within(row()).getByRole("menuitem", { name: /Seal Data/ }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("withholds the row Seal Data when POST /api/v1/vtpm/bundles/{id}/seal is not offered", async () => {
    offExcept([SEAL_OP]);
    render(<VTPMPage />);
    await screen.findAllByText("vm-alpha");

    const seal = within(row()).getByRole("menuitem", { name: /Seal Data/ });
    expectWithheld(seal);
    seal.click();
    expect(push).not.toHaveBeenCalled();
  });

  it("leaves every control enabled when the server offers the vTPM ops", async () => {
    render(<VTPMPage />);
    await screen.findAllByText("vm-alpha");

    for (const op of [LIST_OP, CREATE_OP, DELETE_OP, SEAL_OP]) {
      expect(capability).toHaveBeenCalledWith(op);
    }
    expect(screen.queryByTestId("vtpm-not-enabled")).toBeNull();
    const create = screen.getByRole("button", { name: /Create vTPM/ }) as HTMLButtonElement;
    expect(create.disabled).toBe(false);
    expect(create.getAttribute("data-capability-enabled")).toBe("true");
    for (const item of [/Delete/, /Seal Data/]) {
      expect((within(row()).getByRole("menuitem", { name: item }) as HTMLButtonElement).disabled).toBe(false);
    }
  });
});
