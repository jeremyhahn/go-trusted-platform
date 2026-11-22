import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { DNSRecord } from "@/types/infrastructure";

const { dns, toast } = vi.hoisted(() => ({
  dns: { deleteRecord: vi.fn() },
  toast: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useDNS: () => dns,
  useToast: () => ({ toast }),
}));

import { DNSRecordTable } from "./dns-record-table";

const records: DNSRecord[] = [
  {
    id: "SRV-sip-1",
    name: "_sip._tcp",
    type: "SRV",
    value: "sip1.example.com.",
    ttl: 300,
    priority: 10,
    weight: 20,
    port: 5060,
  },
  {
    id: "SRV-sip-2",
    name: "_sip._tcp",
    type: "SRV",
    value: "sip2.example.com.",
    ttl: 300,
    priority: 20,
    weight: 10,
    port: 5060,
  },
  {
    id: "SRV-ldap",
    name: "_ldap._tcp",
    type: "SRV",
    value: "ldap.example.com.",
    ttl: 300,
    priority: 10,
    weight: 10,
    port: 389,
  },
  {
    id: "A-www",
    name: "www",
    type: "A",
    value: "www-target",
    ttl: 3600,
  },
];

function trigger(value: string): HTMLButtonElement {
  const row = screen.getByText(value).closest("tr");
  if (!row) throw new Error(`no row for ${value}`);
  return within(row).getByRole("button") as HTMLButtonElement;
}

function renderTable() {
  render(
    <DNSRecordTable
      zoneName="example.com"
      records={records}
      onRefresh={vi.fn()}
      onEdit={vi.fn()}
    />,
  );
}

beforeEach(() => {
  dns.deleteRecord.mockReset();
  toast.mockReset();
  dns.deleteRecord.mockResolvedValue({ data: {} });
});

afterEach(() => {
  cleanup();
});

describe("DNSRecordTable SRV owners (#2060)", () => {
  it("disables Edit and Delete on SRV rows that share an owner name", () => {
    renderTable();

    expect(trigger("sip1.example.com.").disabled).toBe(true);
    expect(trigger("sip2.example.com.").disabled).toBe(true);
    expect(trigger("ldap.example.com.").disabled).toBe(false);
    expect(trigger("www-target").disabled).toBe(false);
    expect(dns.deleteRecord).not.toHaveBeenCalled();
  });

  it("says why a shared SRV owner has no row actions", () => {
    renderTable();

    for (const value of ["sip1.example.com.", "sip2.example.com."]) {
      expect(trigger(value).getAttribute("title") ?? "").toContain("share");
    }
  });
});
