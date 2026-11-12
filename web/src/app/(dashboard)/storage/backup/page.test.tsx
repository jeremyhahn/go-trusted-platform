import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import BackupPage from "./page";

// #1826: the backup page lists the QuicBaaS backups through the SDK client,
// maps the wire enums to the UI strings and drives create, delete and
// restore. The client is a stable fake so the real useApi and useMutation
// hooks run against it.

const backups = [
  { backupId: "b-full", name: "nightly-full", type: "FULL", state: "COMPLETED", location: "vault/a", sizeBytes: 1536, keyCount: 1200, checksum: "abc", startedAt: "2026-11-01T00:00:00Z" },
  { backupId: "b-incr", name: "hourly-incr", type: "INCREMENTAL", state: "IN_PROGRESS" },
  { backupId: "b-diff", name: "weekly-diff", type: "DIFFERENTIAL", state: "FAILED" },
  { backupId: "b-odd", name: "odd-backup", type: "UNSPECIFIED", state: "BOGUS" },
];

const client = {
  quicBaaSBackup: {
    list: vi.fn(),
    create: vi.fn(),
    delete: vi.fn(),
    restore: vi.fn(),
  },
};
const toast = vi.fn();

// The SDK client answers with an ApiResponse: data on success, error on refusal.
const ok = (data: unknown) => ({ data });
const refused = (message: string) => ({ error: { code: "REFUSED", message } });
const toastResult = { toast };

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  usePlatformClient: () => client,
  useToast: () => toastResult,
}));

// The Radix menu's portal does not settle in jsdom, so row menus render inline.
vi.mock("@/components/ui/dropdown-menu", async (importOriginal) => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Item = ({ children, onClick, disabled }: { children?: React.ReactNode; onClick?: () => void; disabled?: boolean }) => (
    <button type="button" role="menuitem" disabled={disabled} onClick={onClick}>
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

function rowFor(name: string): HTMLElement {
  const row = screen.getByText(name).closest("tr");
  if (!row) throw new Error(`no table row for ${name}`);
  return row;
}

function stat(title: string): string {
  const card = screen.getByText(title).parentElement?.parentElement;
  return card?.querySelector(".text-2xl")?.textContent?.trim() ?? "";
}

describe("BackupPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    client.quicBaaSBackup.list.mockResolvedValue(ok({ backups }));
    client.quicBaaSBackup.create.mockResolvedValue(ok({}));
    client.quicBaaSBackup.delete.mockResolvedValue(ok({}));
    client.quicBaaSBackup.restore.mockResolvedValue(ok({}));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("maps every backup type and state, unknown values included", async () => {
    render(<BackupPage />);
    await screen.findByText("nightly-full");
    expect(within(rowFor("nightly-full")).getByText("full")).toBeTruthy();
    expect(within(rowFor("nightly-full")).getByText("completed")).toBeTruthy();
    expect(within(rowFor("hourly-incr")).getByText("incremental")).toBeTruthy();
    expect(within(rowFor("hourly-incr")).getByText("running")).toBeTruthy();
    expect(within(rowFor("weekly-diff")).getByText("differential")).toBeTruthy();
    expect(within(rowFor("weekly-diff")).getByText("failed")).toBeTruthy();
    expect(within(rowFor("odd-backup")).getByText("full")).toBeTruthy();
    expect(within(rowFor("odd-backup")).getByText("pending")).toBeTruthy();
    expect(client.quicBaaSBackup.list).toHaveBeenCalledWith({});
  });

  it("counts the backups by status", async () => {
    render(<BackupPage />);
    await screen.findByText("nightly-full");
    expect(stat("Total Backups")).toBe("4");
    expect(stat("Completed")).toBe("1");
    expect(stat("Failed")).toBe("1");
    expect(stat("In Progress")).toBe("1");
  });

  it("formats the size and key count, and shows a dash when they are absent", async () => {
    render(<BackupPage />);
    await screen.findByText("nightly-full");
    const full = within(rowFor("nightly-full"));
    expect(full.getByText("1.5 KB")).toBeTruthy();
    expect(full.getByText((1200).toLocaleString())).toBeTruthy();
    expect(full.getByText("vault/a")).toBeTruthy();
    expect(within(rowFor("hourly-incr")).getAllByText("-").length).toBeGreaterThanOrEqual(4);
  });

  it("shows the empty state when the list has no backups", async () => {
    client.quicBaaSBackup.list.mockResolvedValue(ok({}));
    render(<BackupPage />);
    expect(await screen.findByText("No backups found")).toBeTruthy();
    expect(stat("Total Backups")).toBe("0");
  });

  it("shows the error and a destructive toast when the list fails", async () => {
    client.quicBaaSBackup.list.mockRejectedValue(new Error("backup service down"));
    render(<BackupPage />);
    expect(await screen.findByText("backup service down")).toBeTruthy();
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error loading backups", variant: "destructive" }),
      ),
    );
  });

  it("refuses to start a backup without a name", async () => {
    render(<BackupPage />);
    await screen.findByText("nightly-full");
    fireEvent.click(screen.getByRole("button", { name: /Create Backup/ }));
    fireEvent.change(await screen.findByLabelText("Backup Name"), { target: { value: "   " } });
    fireEvent.click(screen.getByRole("button", { name: "Start Backup" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Validation error" })),
    );
    expect(client.quicBaaSBackup.create).not.toHaveBeenCalled();
  });

  it("starts a backup with the name, description and compression the operator enters", async () => {
    render(<BackupPage />);
    await screen.findByText("nightly-full");
    fireEvent.click(screen.getByRole("button", { name: /Create Backup/ }));
    fireEvent.change(await screen.findByLabelText("Backup Name"), { target: { value: "pre-deploy" } });
    fireEvent.change(screen.getByLabelText("Description (optional)"), { target: { value: "before v2" } });
    fireEvent.click(screen.getByLabelText("Enable compression"));
    fireEvent.click(screen.getByRole("button", { name: "Start Backup" }));
    await waitFor(() =>
      expect(client.quicBaaSBackup.create).toHaveBeenCalledWith({
        name: "pre-deploy",
        type: "FULL",
        location: undefined,
        compression: false,
        tags: { description: "before v2" },
      }),
    );
    await waitFor(() => expect(screen.queryByLabelText("Backup Name")).toBeNull());
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Backup started" }));
    expect(client.quicBaaSBackup.list).toHaveBeenCalledTimes(2);
  });

  it("sends a location and no tags when there is no description", async () => {
    render(<BackupPage />);
    await screen.findByText("nightly-full");
    fireEvent.click(screen.getByRole("button", { name: /Create Backup/ }));
    fireEvent.change(await screen.findByLabelText("Backup Name"), { target: { value: "to-vault" } });
    fireEvent.change(screen.getByLabelText("Storage Location (optional)"), { target: { value: "vault/b" } });
    fireEvent.click(screen.getByRole("button", { name: "Start Backup" }));
    await waitFor(() =>
      expect(client.quicBaaSBackup.create).toHaveBeenCalledWith({
        name: "to-vault",
        type: "FULL",
        location: "vault/b",
        compression: true,
        tags: undefined,
      }),
    );
  });

  it("keeps the create dialog open when the backup is refused", async () => {
    client.quicBaaSBackup.create.mockResolvedValue(refused("quota exceeded"));
    render(<BackupPage />);
    await screen.findByText("nightly-full");
    fireEvent.click(screen.getByRole("button", { name: /Create Backup/ }));
    fireEvent.change(await screen.findByLabelText("Backup Name"), { target: { value: "too-big" } });
    fireEvent.click(screen.getByRole("button", { name: "Start Backup" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error creating backup", description: "quota exceeded" }),
      ),
    );
    expect(screen.getByLabelText("Backup Name")).toBeTruthy();
  });

  it("deletes a backup only after confirmation", async () => {
    const confirm = vi.fn().mockReturnValueOnce(false).mockReturnValueOnce(true);
    vi.stubGlobal("confirm", confirm);
    render(<BackupPage />);
    await screen.findByText("nightly-full");
    const del = within(rowFor("weekly-diff")).getByRole("menuitem", { name: /Delete/ });
    fireEvent.click(del);
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(client.quicBaaSBackup.delete).not.toHaveBeenCalled();
    fireEvent.click(del);
    await waitFor(() => expect(client.quicBaaSBackup.delete).toHaveBeenCalledWith({ backupId: "b-diff" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Backup deleted" })),
    );
  });

  it("reports a refused delete", async () => {
    vi.stubGlobal("confirm", vi.fn(() => true));
    client.quicBaaSBackup.delete.mockResolvedValue(refused("locked"));
    render(<BackupPage />);
    await screen.findByText("nightly-full");
    fireEvent.click(within(rowFor("nightly-full")).getByRole("menuitem", { name: /Delete/ }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error deleting backup", description: "locked" }),
      ),
    );
  });

  it("offers restore only on a completed backup", async () => {
    render(<BackupPage />);
    await screen.findByText("nightly-full");
    const restore = (name: string) =>
      within(rowFor(name)).getByRole("menuitem", { name: /Restore/ }) as HTMLButtonElement;
    expect(restore("nightly-full").disabled).toBe(false);
    expect(restore("hourly-incr").disabled).toBe(true);
    expect(restore("weekly-diff").disabled).toBe(true);
    expect(restore("odd-backup").disabled).toBe(true);
  });

  it("restores a backup with the target prefix and overwrite flag", async () => {
    render(<BackupPage />);
    await screen.findByText("nightly-full");
    fireEvent.click(within(rowFor("nightly-full")).getByRole("menuitem", { name: /Restore/ }));
    fireEvent.change(await screen.findByLabelText("Target Prefix (optional)"), { target: { value: "restored/" } });
    fireEvent.click(screen.getByLabelText("Overwrite existing keys"));
    fireEvent.click(screen.getByRole("button", { name: "Start Restore" }));
    await waitFor(() =>
      expect(client.quicBaaSBackup.restore).toHaveBeenCalledWith({
        backupId: "b-full",
        targetPrefix: "restored/",
        overwrite: true,
      }),
    );
    await waitFor(() => expect(screen.queryByLabelText("Target Prefix (optional)")).toBeNull());
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Restore started" }));
  });

  it("restores to the original location when no prefix is given, and reports a refusal", async () => {
    client.quicBaaSBackup.restore.mockResolvedValue(refused("backup corrupt"));
    render(<BackupPage />);
    await screen.findByText("nightly-full");
    fireEvent.click(within(rowFor("nightly-full")).getByRole("menuitem", { name: /Restore/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Start Restore" }));
    await waitFor(() =>
      expect(client.quicBaaSBackup.restore).toHaveBeenCalledWith({
        backupId: "b-full",
        targetPrefix: undefined,
        overwrite: false,
      }),
    );
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error restoring backup", description: "backup corrupt" }),
      ),
    );
    expect(screen.getByLabelText("Target Prefix (optional)")).toBeTruthy();
  });
});
