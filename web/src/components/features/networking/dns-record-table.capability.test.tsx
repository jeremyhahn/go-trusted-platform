import type { ComponentProps, ReactNode } from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { DNSRecord } from "@/types/infrastructure";

const { dns, toast, off } = vi.hoisted(() => ({
  dns: { deleteRecord: vi.fn() },
  toast: vi.fn(),
  off: new Set<string>(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useDNS: () => dns,
  useToast: () => ({ toast }),
}));

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: "not-configured: dns" } : { enabled: true },
  }),
}));

// Passthrough menu so the items render without opening Radix.
vi.mock("@/components/ui/dropdown-menu", () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: (props: ComponentProps<"button">) => (
    <button type="button" role="menuitem" {...props} />
  ),
}));

import { DNSRecordTable } from "./dns-record-table";

const EDIT_OP = "PUT /api/v1/dns/zones/{zone}/records";
const DELETE_OP = "DELETE /api/v1/dns/zones/{zone}/records/{type}/{name}";

const www: DNSRecord = { id: "A-www", name: "www", type: "A", value: "192.0.2.10", ttl: 3600 };

beforeEach(() => {
  dns.deleteRecord.mockReset();
  toast.mockReset();
  dns.deleteRecord.mockResolvedValue({ data: {} });
});

afterEach(() => {
  cleanup();
  off.clear();
});

const item = (name: string) => screen.getByRole("menuitem", { name }) as HTMLButtonElement;

describe("DNSRecordTable capability gate (#2060)", () => {
  it("withholds Edit and Delete with the server's reason when the server does not offer them", () => {
    off.add(EDIT_OP);
    off.add(DELETE_OP);
    const onEdit = vi.fn();
    render(
      <DNSRecordTable zoneName="example.com" records={[www]} onRefresh={vi.fn()} onEdit={onEdit} />,
    );

    for (const [name, op] of [
      ["Edit", EDIT_OP],
      ["Delete", DELETE_OP],
    ] as const) {
      const el = item(name);
      expect(el.disabled).toBe(true);
      expect(el.getAttribute("title")).toBe("not-configured: dns");
      expect(el.getAttribute("data-capability-op")).toBe(op);
      expect(el.getAttribute("data-capability-enabled")).toBe("false");
    }

    fireEvent.click(item("Edit"));
    fireEvent.click(item("Delete"));
    expect(onEdit).not.toHaveBeenCalled();
    expect(dns.deleteRecord).not.toHaveBeenCalled();
  });

  it("leaves Edit and Delete enabled when the server offers them", async () => {
    const onEdit = vi.fn();
    render(
      <DNSRecordTable zoneName="example.com" records={[www]} onRefresh={vi.fn()} onEdit={onEdit} />,
    );

    expect(item("Edit").getAttribute("data-capability-enabled")).toBe("true");
    expect(item("Delete").getAttribute("data-capability-enabled")).toBe("true");
    expect(item("Edit").disabled).toBe(false);
    expect(item("Delete").disabled).toBe(false);

    fireEvent.click(item("Edit"));
    expect(onEdit).toHaveBeenCalledWith(www);

    fireEvent.click(item("Delete"));
    await waitFor(() =>
      expect(dns.deleteRecord).toHaveBeenCalledWith(
        expect.objectContaining({ zoneName: "example.com", name: "www" }),
      ),
    );
  });

  it("gates Delete alone when only DELETE is withheld", () => {
    off.add(DELETE_OP);
    const onEdit = vi.fn();
    render(
      <DNSRecordTable zoneName="example.com" records={[www]} onRefresh={vi.fn()} onEdit={onEdit} />,
    );

    expect(item("Edit").getAttribute("data-capability-enabled")).toBe("true");
    expect(item("Delete").disabled).toBe(true);
    expect(item("Delete").getAttribute("data-capability-op")).toBe(DELETE_OP);
  });
});
