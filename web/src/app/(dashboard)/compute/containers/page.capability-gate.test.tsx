import * as React from "react";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the containers page lists, creates, starts, stops and deletes
// through useCompute (network boundary, mocked here) and gates the list and
// every control on the server's capabilities.

const { compute, toast, capability, caps } = vi.hoisted(() => ({
  compute: {
    listContainers: vi.fn(),
    createContainer: vi.fn(),
    startContainer: vi.fn(),
    stopContainer: vi.fn(),
    deleteContainer: vi.fn(),
  },
  toast: vi.fn(),
  capability: vi.fn(),
  caps: { loading: false },
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useCompute: () => compute,
  useToast: () => ({ toast }),
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

import ContainersPage from "./page";

const LIST_OP = "GET /api/v1/compute/containers";
const CREATE_OP = "POST /api/v1/compute/containers";
const START_OP = "POST /api/v1/compute/containers/{id}/start";
const STOP_OP = "POST /api/v1/compute/containers/{id}/stop";
const DELETE_OP = "DELETE /api/v1/compute/containers/{id}";
const REASON = "blocked: integration";

const containers = [
  { id: "c-run", state: "CONTAINER_STATE_RUNNING", config: { name: "web-run", image: "nginx" }, createdAt: new Date().toISOString() },
  { id: "c-stop", state: "CONTAINER_STATE_STOPPED", config: { name: "web-stop", image: "nginx" }, createdAt: new Date().toISOString() },
];

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

function rowOf(name: string): HTMLElement {
  return screen.getByText(name).closest("tr") as HTMLElement;
}

beforeEach(() => {
  for (const fn of Object.values(compute)) fn.mockReset();
  compute.listContainers.mockResolvedValue({ data: { containers } });
  toast.mockReset();
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
  caps.loading = false;
});

afterEach(() => {
  cleanup();
});

describe("ContainersPage capability gate", () => {
  it("shows the Compute unavailable view with the server's reason and does not list when GET /api/v1/compute/containers is not offered", async () => {
    offExcept([LIST_OP]);
    render(<ContainersPage />);

    const view = await screen.findByTestId("containers-not-enabled");
    expect(view.textContent).toContain(REASON);
    expect(compute.listContainers).not.toHaveBeenCalled();
  });

  it("shows the loading state and does not list while the capabilities load", async () => {
    caps.loading = true;
    capability.mockImplementation(() => ({ enabled: false, reason: "loading" }));
    const { container } = render(<ContainersPage />);

    expect(container.querySelector(".animate-spin")).not.toBeNull();
    expect(screen.queryByTestId("containers-not-enabled")).toBeNull();
    expect(compute.listContainers).not.toHaveBeenCalled();
  });

  it("withholds Create Container when POST /api/v1/compute/containers is not offered", async () => {
    offExcept([CREATE_OP]);
    render(<ContainersPage />);
    await screen.findByText("web-run");

    expectWithheld(screen.getByRole("button", { name: /Create Container/ }), CREATE_OP);
  });

  it("withholds the row Start, Stop and Delete when their ops are not offered", async () => {
    offExcept([START_OP, STOP_OP, DELETE_OP]);
    render(<ContainersPage />);
    await screen.findByText("web-run");

    expectWithheld(within(rowOf("web-run")).getByRole("menuitem", { name: /Stop/ }));
    expectWithheld(within(rowOf("web-run")).getByRole("menuitem", { name: /Delete/ }));
    const start = within(rowOf("web-stop")).getByRole("menuitem", { name: /Start/ });
    expectWithheld(start);
    start.click();
    expect(compute.startContainer).not.toHaveBeenCalled();
  });

  it("leaves every control enabled when the server offers the container ops", async () => {
    render(<ContainersPage />);
    await screen.findByText("web-run");

    for (const op of [LIST_OP, CREATE_OP, START_OP, STOP_OP, DELETE_OP]) {
      expect(capability).toHaveBeenCalledWith(op);
    }
    expect(screen.queryByTestId("containers-not-enabled")).toBeNull();
    const create = screen.getByRole("button", { name: /Create Container/ }) as HTMLButtonElement;
    expect(create.disabled).toBe(false);
    expect(create.getAttribute("data-capability-enabled")).toBe("true");
    const refresh = document.querySelector(`[data-capability-op="${LIST_OP}"]`) as HTMLButtonElement;
    expect(refresh).not.toBeNull();
    expect(refresh.disabled).toBe(false);
    for (const [name, item] of [
      ["web-run", /Stop/],
      ["web-run", /Delete/],
      ["web-stop", /Start/],
    ] as const) {
      expect((within(rowOf(name)).getByRole("menuitem", { name: item }) as HTMLButtonElement).disabled).toBe(false);
    }
  });
});
