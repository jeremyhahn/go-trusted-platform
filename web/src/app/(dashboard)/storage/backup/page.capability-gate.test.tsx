import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the backup page gates its list, create, restore and delete
// controls on the server's capabilities. The SDK client is a fake (network
// boundary); useApi and useMutation run for real against it.

const { client, toast, capability } = vi.hoisted(() => ({
  client: {
    quicBaaSBackup: { list: vi.fn(), create: vi.fn(), delete: vi.fn(), restore: vi.fn() },
  },
  toast: vi.fn(),
  capability: vi.fn(),
}));
const toastResult = { toast };

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  usePlatformClient: () => client,
  useToast: () => toastResult,
}));

// #2033 item 5: the page and Gated read the server's capabilities through this hook.
vi.mock("@/hooks/use-capabilities", () => ({ useCapabilities: () => ({ loading: false, error: undefined, capability }) }));

// The Radix menu's portal does not settle in jsdom, so row menus render inline.
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
    <button type="button" role="menuitem" disabled={disabled} title={title} onClick={onClick}>
      {children}
    </button>
  );
  return {
    ...(await importOriginal<typeof import("@/components/ui/dropdown-menu")>()),
    DropdownMenu: Pass,
    DropdownMenuTrigger: Pass,
    DropdownMenuContent: Pass,
    DropdownMenuSeparator: () => null,
    DropdownMenuItem: Item,
  };
});

import BackupPage from "./page";

const LIST_OP = "GET /api/v1/quicbaas/backups";
const CREATE_OP = "POST /api/v1/quicbaas/backups";
const RESTORE_OP = "POST /api/v1/quicbaas/backups/{backup_id}/restore";
const DELETE_OP = "DELETE /api/v1/quicbaas/backups/{backup_id}";
const NOT_OFFERED = "not offered by this server";

const backups = [
  { backupId: "b-full", name: "nightly-full", type: "FULL", state: "COMPLETED" },
  { backupId: "b-diff", name: "weekly-diff", type: "DIFFERENTIAL", state: "FAILED" },
];
const ok = (data: unknown) => ({ data });

function offerAllBut(off: string, reason: string) {
  capability.mockImplementation((op: string) => (op === off ? { enabled: false, reason } : { enabled: true }));
}

function rowFor(name: string): HTMLElement {
  const row = screen.getByText(name).closest("tr");
  if (!row) throw new Error(`no table row for ${name}`);
  return row;
}

function menuItem(name: string, item: RegExp): HTMLButtonElement {
  return within(rowFor(name)).getByRole("menuitem", { name: item }) as HTMLButtonElement;
}

function button(text: string | RegExp): HTMLButtonElement {
  return screen.getByText(text, { selector: "button" }) as HTMLButtonElement;
}

function expectWithheld(control: HTMLElement, op: string, reason: string) {
  expect((control as HTMLButtonElement).disabled).toBe(true);
  expect(control.getAttribute("title")).toBe(reason);
  expect(control.getAttribute("data-capability-op")).toBe(op);
  expect(control.getAttribute("data-capability-enabled")).toBe("false");
}

function expectOffered(control: HTMLElement) {
  expect((control as HTMLButtonElement).disabled).toBe(false);
  expect(control.getAttribute("title")).toBeNull();
}

beforeEach(() => {
  vi.clearAllMocks();
  client.quicBaaSBackup.list.mockResolvedValue(ok({ backups }));
  client.quicBaaSBackup.create.mockResolvedValue(ok({}));
  client.quicBaaSBackup.delete.mockResolvedValue(ok({}));
  client.quicBaaSBackup.restore.mockResolvedValue(ok({}));
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("BackupPage capability gate", () => {
  it("shows the not-enabled card with the server's reason and does not list when GET /api/v1/quicbaas/backups is not offered", async () => {
    offerAllBut(LIST_OP, "blocked: integration");
    render(<BackupPage />);

    const card = await screen.findByTestId("backup-not-enabled");
    expect(card.textContent).toContain("Backups are not enabled on this server");
    expect(card.textContent).toContain("blocked: integration");
    expectWithheld(button("Refresh"), LIST_OP, "blocked: integration");
    expect(client.quicBaaSBackup.list).not.toHaveBeenCalled();
  });

  it("withholds Create Backup, Start Backup and Create your first backup when POST /api/v1/quicbaas/backups is not offered", async () => {
    offerAllBut(CREATE_OP, "blocked: integration");
    client.quicBaaSBackup.list.mockResolvedValue(ok({}));
    render(<BackupPage />);
    await screen.findByText("No backups found");

    expectWithheld(button(/Create Backup/), CREATE_OP, "blocked: integration");
    expectWithheld(button(/Create your first backup/), CREATE_OP, "blocked: integration");
    fireEvent.click(button(/Create your first backup/));
    expect(screen.queryByLabelText("Backup Name")).toBeNull();
    cleanup();

    // Start Backup inside an open dialog follows the gate when it goes dark.
    capability.mockImplementation(() => ({ enabled: true }));
    render(<BackupPage />);
    await screen.findByText("No backups found");
    fireEvent.click(button(/Create Backup/));
    const name = await screen.findByLabelText("Backup Name");
    offerAllBut(CREATE_OP, "blocked: integration");
    fireEvent.change(name, { target: { value: "pre-deploy" } });
    const start = button("Start Backup");
    expectWithheld(start, CREATE_OP, "blocked: integration");
    fireEvent.click(start);
    expect(client.quicBaaSBackup.create).not.toHaveBeenCalled();
  });

  it("withholds Restore and Start Restore when POST /api/v1/quicbaas/backups/{backup_id}/restore is not offered", async () => {
    offerAllBut(RESTORE_OP, NOT_OFFERED);
    render(<BackupPage />);
    await screen.findByText("nightly-full");

    const restore = menuItem("nightly-full", /Restore/);
    expect(restore.disabled).toBe(true);
    expect(restore.getAttribute("title")).toBe(NOT_OFFERED);
    fireEvent.click(restore);
    expect(screen.queryByText("Restore Backup")).toBeNull();
    cleanup();

    // Start Restore inside an open dialog follows the gate when it goes dark.
    capability.mockImplementation(() => ({ enabled: true }));
    render(<BackupPage />);
    await screen.findByText("nightly-full");
    fireEvent.click(menuItem("nightly-full", /Restore/));
    const target = await screen.findByLabelText("Target Prefix (optional)");
    offerAllBut(RESTORE_OP, NOT_OFFERED);
    fireEvent.change(target, { target: { value: "restored/" } });
    const start = button("Start Restore");
    expectWithheld(start, RESTORE_OP, NOT_OFFERED);
    fireEvent.click(start);
    expect(client.quicBaaSBackup.restore).not.toHaveBeenCalled();
  });

  it("withholds the row Delete and the bulk delete when DELETE /api/v1/quicbaas/backups/{backup_id} is not offered", async () => {
    const confirm = vi.fn(() => true);
    vi.stubGlobal("confirm", confirm);
    offerAllBut(DELETE_OP, NOT_OFFERED);
    render(<BackupPage />);
    await screen.findByText("nightly-full");

    const del = menuItem("weekly-diff", /Delete/);
    expect(del.disabled).toBe(true);
    expect(del.getAttribute("title")).toBe(NOT_OFFERED);
    fireEvent.click(del);

    fireEvent.click(within(rowFor("weekly-diff")).getByRole("checkbox", { name: "Select row" }));
    const bulk = button("Delete selected (1)");
    expect(bulk.disabled).toBe(true);
    expect(bulk.getAttribute("title")).toBe(NOT_OFFERED);
    fireEvent.click(bulk);

    expect(confirm).not.toHaveBeenCalled();
    expect(client.quicBaaSBackup.delete).not.toHaveBeenCalled();
  });

  it("leaves every control enabled when the server offers the backup ops", async () => {
    render(<BackupPage />);
    await screen.findByText("nightly-full");

    expect(client.quicBaaSBackup.list).toHaveBeenCalledTimes(1);
    expect(screen.queryByTestId("backup-not-enabled")).toBeNull();
    for (const op of [LIST_OP, CREATE_OP, RESTORE_OP, DELETE_OP]) expect(capability).toHaveBeenCalledWith(op);
    expectOffered(button("Refresh"));
    expect(button("Refresh").getAttribute("data-capability-op")).toBe(LIST_OP);
    expectOffered(button(/Create Backup/));
    expect(button(/Create Backup/).getAttribute("data-capability-enabled")).toBe("true");
    expectOffered(menuItem("nightly-full", /Restore/));
    expectOffered(menuItem("nightly-full", /Delete/));
    fireEvent.click(within(rowFor("weekly-diff")).getByRole("checkbox", { name: "Select row" }));
    expectOffered(button("Delete selected (1)"));

    fireEvent.click(menuItem("nightly-full", /Restore/));
    await screen.findByLabelText("Target Prefix (optional)");
    expectOffered(button("Start Restore"));
    expect(button("Start Restore").getAttribute("data-capability-op")).toBe(RESTORE_OP);
    cleanup();

    client.quicBaaSBackup.list.mockResolvedValue(ok({}));
    render(<BackupPage />);
    await screen.findByText("No backups found");
    expectOffered(button(/Create your first backup/));
    expect(button(/Create your first backup/).getAttribute("data-capability-op")).toBe(CREATE_OP);
    fireEvent.click(button(/Create Backup/));
    await screen.findByLabelText("Backup Name");
    expectOffered(button("Start Backup"));
    expect(button("Start Backup").getAttribute("data-capability-op")).toBe(CREATE_OP);
  });
});
