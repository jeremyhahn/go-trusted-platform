import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Container } from "@/types/infrastructure";

import { ContainerTable } from "./container-table";

// #1816: ContainerTable lists containers and offers start, stop, logs, shell
// and delete per row according to the container's status. Only the compute
// client and the toast are stubbed; useMutation is the real one.

const compute = {
  startContainer: vi.fn(),
  stopContainer: vi.fn(),
  deleteContainer: vi.fn(),
};
const toastMock = vi.fn();

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useCompute: () => compute,
  useToast: () => ({ toast: toastMock }),
}));

// Radix's menu does not open in jsdom; render each row's items inline, as
// device-table.test.tsx does.
vi.mock("@/components/ui/dropdown-menu", () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: ({ children, onClick }: { children: ReactNode; onClick?: () => void }) => (
    <div role="menuitem" onClick={onClick}>
      {children}
    </div>
  ),
}));

const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();

function container(over: Partial<Container> = {}): Container {
  return {
    id: "c1",
    name: "web",
    image: "nginx:1.27",
    status: "running",
    ports: [],
    createdAt: twoDaysAgo,
    ...over,
  };
}

function row(name: string): HTMLElement {
  return screen.getByText(name).closest("tr") as HTMLElement;
}

/** The row's actions menu. */
async function openMenu(name: string) {
  return within(row(name)).getByRole("menu");
}

async function choose(name: string, item: string) {
  const menu = await openMenu(name);
  await act(async () => {
    fireEvent.click(within(menu).getByRole("menuitem", { name: item }));
  });
}

function itemNames(menu: HTMLElement): string[] {
  return within(menu)
    .getAllByRole("menuitem")
    .map((el) => el.textContent?.trim() ?? "");
}

describe("ContainerTable", () => {
  beforeEach(() => {
    for (const fn of Object.values(compute)) fn.mockReset();
    toastMock.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("says when there are no containers", () => {
    render(<ContainerTable containers={[]} onRefresh={vi.fn()} />);
    expect(screen.getByText("No containers found")).toBeTruthy();
  });

  it("shows each container's name, image, status, ports and age", () => {
    render(
      <ContainerTable
        containers={[
          container({
            ports: [
              { host: 8080, container: 80, protocol: "tcp" },
              { host: 5353, container: 53, protocol: "udp" },
            ],
          }),
          container({ id: "c2", name: "db", image: "postgres:17", status: "error" }),
        ]}
        onRefresh={vi.fn()}
      />
    );
    const web = row("web");
    expect(within(web).getByText("nginx:1.27")).toBeTruthy();
    expect(within(web).getByText("running")).toBeTruthy();
    expect(within(web).getByText("8080:80/tcp, 5353:53/udp")).toBeTruthy();
    expect(within(web).getByText("2 days ago")).toBeTruthy();
    const db = row("db");
    expect(within(db).getByText("error")).toBeTruthy();
    expect(within(db).getByText("-")).toBeTruthy();
    expect(screen.queryByText("No containers found")).toBeNull();
  });

  it("colours the status badge by status", () => {
    render(
      <ContainerTable
        containers={[
          container({ id: "a", name: "a", status: "running" }),
          container({ id: "b", name: "b", status: "stopped" }),
          container({ id: "c", name: "c", status: "creating" }),
          container({ id: "d", name: "d", status: "error" }),
        ]}
        onRefresh={vi.fn()}
      />
    );
    expect(within(row("a")).getByText("running").className).toContain("text-green-500");
    expect(within(row("b")).getByText("stopped").className).toContain("text-gray-500");
    expect(within(row("c")).getByText("creating").className).toContain("text-blue-500");
    expect(within(row("d")).getByText("error").className).toContain("text-red-500");
  });

  it("offers stop, logs, shell and delete for a running container", async () => {
    render(
      <ContainerTable
        containers={[container()]}
        onRefresh={vi.fn()}
        onLogs={vi.fn()}
        onShell={vi.fn()}
      />
    );
    expect(itemNames(await openMenu("web"))).toEqual(["Stop", "Logs", "Shell", "Delete"]);
  });

  it("leaves out logs and shell when no handler is given", async () => {
    render(<ContainerTable containers={[container()]} onRefresh={vi.fn()} />);
    expect(itemNames(await openMenu("web"))).toEqual(["Stop", "Delete"]);
  });

  it("offers only start and delete for a container that is not running", async () => {
    render(
      <ContainerTable
        containers={[container({ status: "stopped" })]}
        onRefresh={vi.fn()}
        onLogs={vi.fn()}
        onShell={vi.fn()}
      />
    );
    expect(itemNames(await openMenu("web"))).toEqual(["Start", "Delete"]);
  });

  it("passes the container to the logs and shell handlers", async () => {
    const onLogs = vi.fn();
    const onShell = vi.fn();
    const c = container();
    render(<ContainerTable containers={[c]} onRefresh={vi.fn()} onLogs={onLogs} onShell={onShell} />);
    await choose("web", "Logs");
    expect(onLogs).toHaveBeenCalledWith(c);
    await choose("web", "Shell");
    expect(onShell).toHaveBeenCalledWith(c);
  });

  it.each([
    ["Start", "stopped", "startContainer", "c1", "Container started successfully"],
    ["Stop", "running", "stopContainer", { id: "c1" }, "Container stopped successfully"],
    ["Delete", "running", "deleteContainer", { id: "c1" }, "Container deleted successfully"],
  ] as const)(
    "%s calls the client, toasts success and refreshes",
    async (item, status, method, arg, description) => {
      compute[method].mockResolvedValue({ success: true, data: {} });
      const onRefresh = vi.fn();
      render(<ContainerTable containers={[container({ status })]} onRefresh={onRefresh} />);

      await choose("web", item);

      await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
      expect(compute[method]).toHaveBeenCalledWith(arg);
      expect(toastMock).toHaveBeenCalledWith({ title: "Success", description });
      expect((within(row("web")).getByRole("button") as HTMLButtonElement).disabled).toBe(false);
    }
  );

  it.each([
    ["Start", "stopped", "startContainer", "Failed to start container: denied"],
    ["Stop", "running", "stopContainer", "Failed to stop container: denied"],
    ["Delete", "stopped", "deleteContainer", "Failed to delete container: denied"],
  ] as const)(
    "%s failing toasts the error, does not refresh and re-enables the row",
    async (item, status, method, description) => {
      compute[method].mockResolvedValue({
        success: false,
        error: { code: "PERMISSION_DENIED", message: "denied" },
      });
      const onRefresh = vi.fn();
      render(<ContainerTable containers={[container({ status })]} onRefresh={onRefresh} />);

      await choose("web", item);

      await waitFor(() =>
        expect(toastMock).toHaveBeenCalledWith({ title: "Error", description, variant: "destructive" })
      );
      expect(onRefresh).not.toHaveBeenCalled();
      expect((within(row("web")).getByRole("button") as HTMLButtonElement).disabled).toBe(false);
    }
  );

  it("disables only the busy row's menu while its action runs", async () => {
    compute.stopContainer.mockReturnValue(new Promise(() => {}));
    render(
      <ContainerTable
        containers={[container(), container({ id: "c2", name: "db" })]}
        onRefresh={vi.fn()}
      />
    );

    await choose("web", "Stop");

    expect((within(row("web")).getByRole("button") as HTMLButtonElement).disabled).toBe(true);
    expect((within(row("db")).getByRole("button") as HTMLButtonElement).disabled).toBe(false);
  });
});
