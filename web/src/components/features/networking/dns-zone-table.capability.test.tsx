import type { ComponentProps, ReactNode } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { DNSZone } from "@/types/infrastructure";

const { dns, toast, off, push } = vi.hoisted(() => ({
  dns: { deleteZone: vi.fn() },
  toast: vi.fn(),
  off: new Set<string>(),
  push: vi.fn(),
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

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push }),
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

import { DNSZoneTable } from "./dns-zone-table";

const DELETE_OP = "DELETE /api/v1/dns/zones/{zone}";

function zone(id: string, name: string): DNSZone {
  return {
    id,
    name,
    type: "primary",
    recordCount: 2,
    serial: 1,
    refresh: 3600,
    retry: 600,
    expire: 86400,
    ttl: 3600,
    createdAt: "",
    updatedAt: "",
  };
}

const example = zone("z1", "example.test.");

beforeEach(() => {
  dns.deleteZone.mockReset();
  toast.mockReset();
  push.mockReset();
  dns.deleteZone.mockResolvedValue({ data: {} });
});

afterEach(() => {
  cleanup();
  off.clear();
});

const item = (name: string) => screen.getByRole("menuitem", { name }) as HTMLButtonElement;

describe("DNSZoneTable capability gate", () => {
  it("withholds Delete when DELETE /api/v1/dns/zones/{zone} is not offered", () => {
    off.add(DELETE_OP);
    render(<DNSZoneTable zones={[example]} onRefresh={vi.fn()} />);

    const el = item("Delete");
    expect(el.getAttribute("data-capability-op")).toBe(DELETE_OP);
    expect(el.getAttribute("data-capability-enabled")).toBe("false");
    expect(el.disabled).toBe(true);
    expect(el.getAttribute("title")).toBe("not-configured: dns");

    fireEvent.click(el);
    expect(dns.deleteZone).not.toHaveBeenCalled();
  });

  it("offers Delete when the server offers it", () => {
    render(<DNSZoneTable zones={[example]} onRefresh={vi.fn()} />);

    const el = item("Delete");
    expect(el.getAttribute("data-capability-op")).toBe(DELETE_OP);
    expect(el.getAttribute("data-capability-enabled")).toBe("true");
    expect(el.disabled).toBe(false);
  });

  it("marks the table and each zone row with testids", () => {
    render(
      <DNSZoneTable
        zones={[example, zone("z2", "lab.example.test.")]}
        onRefresh={vi.fn()}
      />,
    );

    expect(screen.getByTestId("dns-zone-table")).toBeTruthy();
    expect(screen.getAllByTestId("dns-zone-row")).toHaveLength(2);
  });
});
