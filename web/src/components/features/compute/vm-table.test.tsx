import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { VM } from "@/types/infrastructure";

import { VMTable } from "./vm-table";

// #1816: VMTable lists virtual machines with their sizes and offers start,
// stop, reboot, console and delete per row according to the VM's status.
// Only the compute client and the toast are stubbed; useMutation is real.

const compute = {
  startVM: vi.fn(),
  stopVM: vi.fn(),
  rebootVM: vi.fn(),
  deleteVM: vi.fn(),
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

const threeHoursAgo = new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString();

function vm(over: Partial<VM> = {}): VM {
  return {
    id: "vm-1",
    name: "db",
    status: "running",
    vcpus: 4,
    memoryMB: 8192,
    storageMB: 51200,
    ipAddress: "10.0.0.5",
    createdAt: threeHoursAgo,
    ...over,
  };
}

function row(name: string): HTMLElement {
  return screen.getByText(name).closest("tr") as HTMLElement;
}

function trigger(name: string): HTMLButtonElement {
  return within(row(name)).getByRole("button") as HTMLButtonElement;
}

function itemNames(name: string): string[] {
  return within(within(row(name)).getByRole("menu"))
    .getAllByRole("menuitem")
    .map((el) => el.textContent?.trim() ?? "");
}

async function choose(name: string, item: string) {
  await act(async () => {
    fireEvent.click(within(row(name)).getByRole("menuitem", { name: item }));
  });
}

describe("VMTable", () => {
  beforeEach(() => {
    for (const fn of Object.values(compute)) fn.mockReset();
    toastMock.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("says when there are no virtual machines", () => {
    render(<VMTable vms={[]} onRefresh={vi.fn()} />);
    expect(screen.getByText("No virtual machines found")).toBeTruthy();
  });

  it("shows each VM's status, vCPUs, sizes, address and age", () => {
    render(<VMTable vms={[vm()]} onRefresh={vi.fn()} />);
    const r = row("db");
    expect(within(r).getByText("running")).toBeTruthy();
    expect(within(r).getByText("4")).toBeTruthy();
    expect(within(r).getByText("8.0 GB")).toBeTruthy();
    expect(within(r).getByText("50.0 GB")).toBeTruthy();
    expect(within(r).getByText("10.0.0.5")).toBeTruthy();
    expect(within(r).getByText("about 3 hours ago")).toBeTruthy();
    expect(screen.queryByText("No virtual machines found")).toBeNull();
  });

  it("shows sizes under 1024 MB in MB, 1024 MB as 1.0 GB, and a missing address as -", () => {
    render(
      <VMTable
        vms={[
          vm({ id: "a", name: "small", memoryMB: 512, storageMB: 1023, ipAddress: undefined }),
          vm({ id: "b", name: "edge", memoryMB: 1024, storageMB: 1536, ipAddress: "" }),
        ]}
        onRefresh={vi.fn()}
      />
    );
    const small = row("small");
    expect(within(small).getByText("512 MB")).toBeTruthy();
    expect(within(small).getByText("1023 MB")).toBeTruthy();
    expect(within(small).getByText("-")).toBeTruthy();
    const edge = row("edge");
    expect(within(edge).getByText("1.0 GB")).toBeTruthy();
    expect(within(edge).getByText("1.5 GB")).toBeTruthy();
    expect(within(edge).getByText("-")).toBeTruthy();
  });

  it("colours the status badge by status", () => {
    render(
      <VMTable
        vms={[
          vm({ id: "a", name: "a", status: "running" }),
          vm({ id: "b", name: "b", status: "stopped" }),
          vm({ id: "c", name: "c", status: "suspended" }),
          vm({ id: "d", name: "d", status: "creating" }),
        ]}
        onRefresh={vi.fn()}
      />
    );
    expect(within(row("a")).getByText("running").className).toContain("text-green-500");
    expect(within(row("b")).getByText("stopped").className).toContain("text-gray-500");
    expect(within(row("c")).getByText("suspended").className).toContain("text-yellow-500");
    expect(within(row("d")).getByText("creating").className).toContain("text-blue-500");
  });

  it("offers stop, reboot, console and delete for a running VM", () => {
    render(<VMTable vms={[vm()]} onRefresh={vi.fn()} onConsole={vi.fn()} />);
    expect(itemNames("db")).toEqual(["Stop", "Reboot", "Console", "Delete"]);
  });

  it("leaves out the console when no handler is given", () => {
    render(<VMTable vms={[vm()]} onRefresh={vi.fn()} />);
    expect(itemNames("db")).toEqual(["Stop", "Reboot", "Delete"]);
  });

  it.each(["stopped", "suspended", "creating"] as const)(
    "offers only start and delete for a %s VM",
    (status) => {
      render(<VMTable vms={[vm({ status })]} onRefresh={vi.fn()} onConsole={vi.fn()} />);
      expect(itemNames("db")).toEqual(["Start", "Delete"]);
    }
  );

  it("passes the VM to the console handler", async () => {
    const onConsole = vi.fn();
    const v = vm();
    render(<VMTable vms={[v]} onRefresh={vi.fn()} onConsole={onConsole} />);
    await choose("db", "Console");
    expect(onConsole).toHaveBeenCalledWith(v);
  });

  it.each([
    ["Start", "stopped", "startVM", "vm-1", "VM started successfully"],
    ["Stop", "running", "stopVM", { id: "vm-1" }, "VM stopped successfully"],
    ["Reboot", "running", "rebootVM", { id: "vm-1" }, "VM rebooted successfully"],
    ["Delete", "stopped", "deleteVM", { id: "vm-1" }, "VM deleted successfully"],
  ] as const)(
    "%s calls the client, toasts success and refreshes",
    async (item, status, method, arg, description) => {
      compute[method].mockResolvedValue({ success: true, data: {} });
      const onRefresh = vi.fn();
      render(<VMTable vms={[vm({ status })]} onRefresh={onRefresh} />);

      await choose("db", item);

      await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
      expect(compute[method]).toHaveBeenCalledWith(arg);
      expect(toastMock).toHaveBeenCalledWith({ title: "Success", description });
      expect(trigger("db").disabled).toBe(false);
    }
  );

  it.each([
    ["Start", "stopped", "startVM", "Failed to start VM: denied"],
    ["Stop", "running", "stopVM", "Failed to stop VM: denied"],
    ["Reboot", "running", "rebootVM", "Failed to reboot VM: denied"],
    ["Delete", "running", "deleteVM", "Failed to delete VM: denied"],
  ] as const)(
    "%s failing toasts the error, does not refresh and re-enables the row",
    async (item, status, method, description) => {
      compute[method].mockResolvedValue({
        success: false,
        error: { code: "PERMISSION_DENIED", message: "denied" },
      });
      const onRefresh = vi.fn();
      render(<VMTable vms={[vm({ status })]} onRefresh={onRefresh} />);

      await choose("db", item);

      await waitFor(() =>
        expect(toastMock).toHaveBeenCalledWith({ title: "Error", description, variant: "destructive" })
      );
      expect(onRefresh).not.toHaveBeenCalled();
      expect(trigger("db").disabled).toBe(false);
    }
  );

  it("toasts a thrown error", async () => {
    compute.rebootVM.mockRejectedValue(new Error("network down"));
    render(<VMTable vms={[vm()]} onRefresh={vi.fn()} />);

    await choose("db", "Reboot");

    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ description: "Failed to reboot VM: network down" })
      )
    );
  });

  it("disables only the busy row's menu while its action runs", async () => {
    compute.rebootVM.mockReturnValue(new Promise(() => {}));
    render(<VMTable vms={[vm(), vm({ id: "vm-2", name: "web" })]} onRefresh={vi.fn()} />);

    await choose("db", "Reboot");

    expect(trigger("db").disabled).toBe(true);
    expect(trigger("web").disabled).toBe(false);
  });
});
