import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import KVStorePage from "./page";

// #1826: the KV page lists the QuicBaaS key-value pairs, decodes their base64
// values (JSON, text, binary, or raw when not base64), groups them by the
// key's first segment and drives put and delete. The KV hook is a stable fake
// so the real useApi and useMutation hooks run against it.

const day = 24 * 60 * 60 * 1000;
const now = Date.now();
const longText = "x".repeat(60);

const kvs = [
  { key: "config/app", value: btoa('{"mode":"strict"}'), version: 3, createdAt: now, modifiedAt: now, expiresAt: now + day },
  { key: "config/motd", value: btoa("hello operator"), version: 1, createdAt: now, modifiedAt: now },
  { key: "blobs/seed", value: btoa("\x00\x01\x02\xff"), version: 2, createdAt: now, modifiedAt: now, expiresAt: now - day },
  { key: "solo", value: "not base64!", version: 1, createdAt: now, modifiedAt: now },
  { key: "config/long", value: btoa(longText), version: 1, createdAt: now, modifiedAt: now },
];

const kv = { list: vi.fn(), put: vi.fn(), delete: vi.fn() };
const toast = vi.fn();
const toastResult = { toast };

// The SDK answers with an ApiResponse: data on success, error on refusal.
const ok = (data: unknown) => ({ data });
const refused = (message: string) => ({ error: { code: "REFUSED", message } });

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useQuicBaaSKV: () => kv,
  useToast: () => toastResult,
}));

// The Radix menu's portal does not settle in jsdom, so row menus render inline.
vi.mock("@/components/ui/dropdown-menu", async (importOriginal) => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Item = ({ children, onClick }: { children?: React.ReactNode; onClick?: () => void }) => (
    <button type="button" role="menuitem" onClick={onClick}>
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

function rowFor(key: string): HTMLElement {
  const row = screen.getByText(key).closest("tr");
  if (!row) throw new Error(`no table row for ${key}`);
  return row;
}

function stat(title: string): string {
  const card = screen.getByText(title).parentElement?.parentElement;
  return card?.querySelector(".text-2xl")?.textContent?.trim() ?? "";
}

async function renderPage() {
  render(<KVStorePage />);
  await screen.findByText("config/app");
}

describe("KVStorePage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    kv.list.mockResolvedValue(ok({ kvs }));
    kv.put.mockResolvedValue(ok({}));
    kv.delete.mockResolvedValue(ok({}));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("lists the entries with values and asks for at most 100", async () => {
    await renderPage();
    expect(kv.list).toHaveBeenCalledWith({ prefix: undefined, includeValues: true, limit: 100 });
    expect(within(rowFor("config/app")).getByText("v3")).toBeTruthy();
  });

  it("decodes JSON, text and binary values, and shows a value that is not base64 as it is", async () => {
    await renderPage();
    const json = within(rowFor("config/app"));
    expect(json.getByText("json")).toBeTruthy();
    expect(json.getByText('{"mode":"strict"}')).toBeTruthy();
    const text = within(rowFor("config/motd"));
    expect(text.getByText("string")).toBeTruthy();
    expect(text.getByText("hello operator")).toBeTruthy();
    const binary = within(rowFor("blobs/seed"));
    expect(binary.getByText("binary")).toBeTruthy();
    expect(binary.getByText(`[binary: ${btoa("\x00\x01\x02\xff").length} bytes encoded]`)).toBeTruthy();
    const raw = within(rowFor("solo"));
    expect(raw.getByText("string")).toBeTruthy();
    expect(raw.getByText("not base64!")).toBeTruthy();
  });

  it("groups keys by their first segment and puts a key without one in default", async () => {
    await renderPage();
    expect(within(rowFor("config/app")).getByText("config")).toBeTruthy();
    expect(within(rowFor("blobs/seed")).getByText("blobs")).toBeTruthy();
    expect(within(rowFor("solo")).getByText("default")).toBeTruthy();
  });

  it("cuts a value longer than 50 characters", async () => {
    await renderPage();
    expect(within(rowFor("config/long")).getByText(`${"x".repeat(50)}...`)).toBeTruthy();
  });

  it("shows Never for an entry without expiry and marks an expired one", async () => {
    await renderPage();
    expect(within(rowFor("config/motd")).getByText("Never")).toBeTruthy();
    const expired = within(rowFor("blobs/seed")).getByText(new Date(now - day).toLocaleDateString(), { selector: "span" });
    expect(expired.className).toContain("text-destructive");
    const live = within(rowFor("config/app")).getByText(new Date(now + day).toLocaleDateString(), { selector: "span" });
    expect(live.className).not.toContain("text-destructive");
  });

  it("counts namespaces, entries and entries with a TTL", async () => {
    await renderPage();
    expect(stat("Namespaces")).toBe("3");
    expect(stat("Total Entries")).toBe("5");
    expect(stat("With TTL")).toBe("2");
  });

  it("lists again under the prefix the operator types, and clears it", async () => {
    await renderPage();
    fireEvent.change(screen.getByPlaceholderText("Filter by key prefix..."), { target: { value: "config/" } });
    await waitFor(() =>
      expect(kv.list).toHaveBeenLastCalledWith({ prefix: "config/", includeValues: true, limit: 100 }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    await waitFor(() =>
      expect(kv.list).toHaveBeenLastCalledWith({ prefix: undefined, includeValues: true, limit: 100 }),
    );
  });

  it("shows the empty state when the store has no entries", async () => {
    kv.list.mockResolvedValue(ok({}));
    render(<KVStorePage />);
    expect(await screen.findByText("No entries found")).toBeTruthy();
    expect(stat("Total Entries")).toBe("0");
  });

  it("shows the error and a destructive toast when the list is refused", async () => {
    kv.list.mockResolvedValue(refused("kv unavailable"));
    render(<KVStorePage />);
    expect(await screen.findByText("kv unavailable")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Error loading entries", variant: "destructive" }),
    );
  });

  it("refuses to save an entry without a key", async () => {
    await renderPage();
    fireEvent.click(screen.getByRole("button", { name: /Add Entry/ }));
    fireEvent.change(await screen.findByLabelText("Key"), { target: { value: "  " } });
    fireEvent.click(screen.getByRole("button", { name: "Save Entry" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Validation error", description: "Key is required" })),
    );
    expect(kv.put).not.toHaveBeenCalled();
  });

  it("saves a new entry with its value base64-encoded and its TTL", async () => {
    await renderPage();
    fireEvent.click(screen.getByRole("button", { name: /Add Entry/ }));
    fireEvent.change(await screen.findByLabelText("Key"), { target: { value: "config/new" } });
    fireEvent.change(screen.getByLabelText("Value"), { target: { value: "fresh" } });
    fireEvent.change(screen.getByLabelText("TTL (seconds, optional)"), { target: { value: "60" } });
    fireEvent.click(screen.getByRole("button", { name: "Save Entry" }));
    await waitFor(() => expect(kv.put).toHaveBeenCalledWith({ key: "config/new", value: btoa("fresh"), ttl: 60 }));
    await waitFor(() => expect(screen.queryByLabelText("Key")).toBeNull());
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Entry created" }));
    expect(kv.list).toHaveBeenCalledTimes(2);
  });

  it("saves without a TTL when the field is emptied", async () => {
    await renderPage();
    fireEvent.click(screen.getByRole("button", { name: /Add Entry/ }));
    fireEvent.change(await screen.findByLabelText("Key"), { target: { value: "k" } });
    const ttl = screen.getByLabelText("TTL (seconds, optional)");
    fireEvent.change(ttl, { target: { value: "5" } });
    fireEvent.change(ttl, { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Save Entry" }));
    await waitFor(() => expect(kv.put).toHaveBeenCalledWith({ key: "k", value: btoa(""), ttl: undefined }));
  });

  it("edits a JSON entry under its fixed key and refuses invalid JSON", async () => {
    await renderPage();
    fireEvent.click(within(rowFor("config/app")).getByRole("menuitem", { name: /Edit/ }));
    expect(await screen.findByText("Edit Entry")).toBeTruthy();
    const key = screen.getByLabelText("Key") as HTMLInputElement;
    expect(key.value).toBe("config/app");
    expect(key.disabled).toBe(true);
    const value = screen.getByLabelText("Value") as HTMLTextAreaElement;
    expect(value.value).toBe('{"mode":"strict"}');
    fireEvent.change(value, { target: { value: "{not json" } });
    fireEvent.click(screen.getByRole("button", { name: "Save Entry" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "Invalid JSON format" })),
    );
    expect(kv.put).not.toHaveBeenCalled();
    fireEvent.change(value, { target: { value: '{"mode":"lax"}' } });
    fireEvent.click(screen.getByRole("button", { name: "Save Entry" }));
    await waitFor(() =>
      expect(kv.put).toHaveBeenCalledWith(
        expect.objectContaining({ key: "config/app", value: btoa('{"mode":"lax"}') }),
      ),
    );
    const ttl = kv.put.mock.calls[0][0].ttl as number;
    expect(ttl).toBeGreaterThan(day / 1000 - 60);
    expect(ttl).toBeLessThanOrEqual(day / 1000);
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Entry updated" }));
  });

  it("keeps the dialog open when the put is refused", async () => {
    kv.put.mockResolvedValue(refused("read-only"));
    await renderPage();
    fireEvent.click(screen.getByRole("button", { name: /Add Entry/ }));
    fireEvent.change(await screen.findByLabelText("Key"), { target: { value: "config/x" } });
    fireEvent.click(screen.getByRole("button", { name: "Save Entry" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error saving entry", description: "read-only" })),
    );
    expect(screen.getByLabelText("Key")).toBeTruthy();
  });

  it("deletes an entry only after confirmation, and reports a refusal", async () => {
    const confirm = vi.fn().mockReturnValueOnce(false).mockReturnValue(true);
    vi.stubGlobal("confirm", confirm);
    await renderPage();
    const del = within(rowFor("solo")).getByRole("menuitem", { name: /Delete/ });
    fireEvent.click(del);
    expect(kv.delete).not.toHaveBeenCalled();
    fireEvent.click(del);
    await waitFor(() => expect(kv.delete).toHaveBeenCalledWith({ key: "solo" }));
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Entry deleted" })));
    kv.delete.mockResolvedValue(refused("locked"));
    // The refetch after the delete re-renders the table: query the row again.
    await waitFor(() => expect(kv.list).toHaveBeenCalledTimes(2));
    fireEvent.click(within(rowFor("solo")).getByRole("menuitem", { name: /Delete/ }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error deleting entry", description: "locked" })),
    );
  });
});
