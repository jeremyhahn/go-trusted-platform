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

describe("DNSRecordTable delete confirm (#2060)", () => {
  it("deletes at once when confirmDelete is not set", async () => {
    const onRefresh = vi.fn();
    render(<DNSRecordTable zoneName="example.test" records={[www]} onRefresh={onRefresh} />);

    fireEvent.click(item("Delete"));
    await waitFor(() => expect(dns.deleteRecord).toHaveBeenCalledTimes(1));
    expect(screen.queryByText("Delete this record?")).toBeNull();
  });

  it("asks first with confirmDelete and sends nothing on Cancel", async () => {
    const onRefresh = vi.fn();
    render(
      <DNSRecordTable zoneName="example.test" records={[www]} onRefresh={onRefresh} confirmDelete />,
    );

    fireEvent.click(item("Delete"));
    expect(dns.deleteRecord).not.toHaveBeenCalled();
    expect(await screen.findByText("Delete this record?")).toBeDefined();
    expect(screen.getByText("A www is removed from example.test.")).toBeDefined();

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByText("Delete this record?")).toBeNull());
    expect(dns.deleteRecord).not.toHaveBeenCalled();
  });

  it("sends the delete after Delete record", async () => {
    const onRefresh = vi.fn();
    render(
      <DNSRecordTable zoneName="example.test" records={[www]} onRefresh={onRefresh} confirmDelete />,
    );

    fireEvent.click(item("Delete"));
    fireEvent.click(await screen.findByRole("button", { name: "Delete record" }));
    await waitFor(() => expect(dns.deleteRecord).toHaveBeenCalledTimes(1));
    expect(dns.deleteRecord).toHaveBeenCalledWith(
      expect.objectContaining({ zoneName: "example.test", name: "www" }),
    );
    await waitFor(() => expect(onRefresh).toHaveBeenCalledTimes(1));
  });

  it("opens no confirm for SRV rows the API cannot tell apart", () => {
    const sip1: DNSRecord = {
      id: "SRV-1",
      name: "_sip._tcp",
      type: "SRV",
      value: "sip1.example.com.",
      ttl: 3600,
      priority: 10,
    };
    const sip2: DNSRecord = { ...sip1, id: "SRV-2", value: "sip2.example.com." };
    render(
      <DNSRecordTable
        zoneName="example.test"
        records={[sip1, sip2]}
        onRefresh={vi.fn()}
        confirmDelete
      />,
    );

    fireEvent.click(screen.getAllByRole("menuitem", { name: "Delete" })[0]);
    expect(screen.queryByText("Delete this record?")).toBeNull();
    expect(dns.deleteRecord).not.toHaveBeenCalled();
  });
});
