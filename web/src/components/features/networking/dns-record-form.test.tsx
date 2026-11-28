import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { DNSRecord } from "@/types/infrastructure";

const { dns, toast, off } = vi.hoisted(() => ({
  dns: { addRecord: vi.fn(), updateRecord: vi.fn() },
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

const CREATE_OP = "POST /api/v1/dns/zones/{zone}/records";
const UPDATE_OP = "PUT /api/v1/dns/zones/{zone}/records";

import { DNSRecordForm } from "./dns-record-form";

const zoneName = "example.com";

const mxRecord: DNSRecord = {
  id: "MX-mail",
  name: "mail",
  type: "MX",
  value: "mx.example.com.",
  ttl: 3600,
  priority: 10,
};

const srvRecord: DNSRecord = {
  id: "SRV-sip",
  name: "_sip._tcp",
  type: "SRV",
  value: "sip.example.com.",
  ttl: 300,
  priority: 10,
  weight: 20,
  port: 5060,
};

function textbox(name: string): HTMLInputElement {
  return screen.getByRole("textbox", { name }) as HTMLInputElement;
}

beforeEach(() => {
  dns.addRecord.mockReset();
  dns.updateRecord.mockReset();
  toast.mockReset();
  dns.addRecord.mockResolvedValue({ data: {} });
  dns.updateRecord.mockResolvedValue({ data: {} });
});

afterEach(() => {
  cleanup();
  off.clear();
});

describe("DNSRecordForm (#2060)", () => {
  it("adds a record through client.dns.addRecord", async () => {
    const onSuccess = vi.fn();
    const onOpenChange = vi.fn();
    render(
      <DNSRecordForm zoneName={zoneName} open onOpenChange={onOpenChange} onSuccess={onSuccess} />,
    );

    fireEvent.change(textbox("Name"), { target: { value: "www" } });
    fireEvent.change(textbox("Value"), { target: { value: "www-target" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(dns.addRecord).toHaveBeenCalledTimes(1));
    expect(dns.addRecord).toHaveBeenCalledWith({
      zoneName: "example.com",
      record: expect.objectContaining({
        type: "A",
        a: { name: "www", value: "www-target", ttl: 3600 },
      }),
    });
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ description: "DNS record created successfully" }),
      ),
    );
    expect(onSuccess).toHaveBeenCalled();
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("updates a record with the old and the new record through client.dns.updateRecord", async () => {
    render(
      <DNSRecordForm
        zoneName={zoneName}
        open
        onOpenChange={vi.fn()}
        onSuccess={vi.fn()}
        record={mxRecord}
      />,
    );

    fireEvent.change(textbox("Value"), { target: { value: "mx2.example.com." } });
    fireEvent.click(screen.getByRole("button", { name: "Update" }));

    await waitFor(() => expect(dns.updateRecord).toHaveBeenCalledTimes(1));
    expect(dns.updateRecord).toHaveBeenCalledWith({
      zoneName: "example.com",
      oldRecord: expect.objectContaining({
        type: "MX",
        mx: { name: "mail", value: "mx.example.com.", ttl: 3600, priority: 10 },
      }),
      newRecord: expect.objectContaining({
        type: "MX",
        mx: { name: "mail", value: "mx2.example.com.", ttl: 3600, priority: 10 },
      }),
    });
  });

  it("sends an edited SRV record's target, priority, weight and port", async () => {
    render(
      <DNSRecordForm
        zoneName={zoneName}
        open
        onOpenChange={vi.fn()}
        onSuccess={vi.fn()}
        record={srvRecord}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Update" }));

    await waitFor(() => expect(dns.updateRecord).toHaveBeenCalledTimes(1));
    const srv = {
      name: "_sip._tcp",
      target: "sip.example.com.",
      ttl: 300,
      priority: 10,
      weight: 20,
      port: 5060,
    };
    expect(dns.updateRecord).toHaveBeenCalledWith({
      zoneName: "example.com",
      oldRecord: expect.objectContaining({ type: "SRV", srv }),
      newRecord: expect.objectContaining({ type: "SRV", srv }),
    });
  });

  it("shows the server's refusal", async () => {
    dns.addRecord.mockResolvedValue({
      error: { code: "PERMISSION_DENIED", message: "zone is read-only" },
    });
    const onSuccess = vi.fn();
    render(
      <DNSRecordForm zoneName={zoneName} open onOpenChange={vi.fn()} onSuccess={onSuccess} />,
    );

    fireEvent.change(textbox("Name"), { target: { value: "www" } });
    fireEvent.change(textbox("Value"), { target: { value: "www-target" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({
          description: "Failed to create record: zone is read-only",
          variant: "destructive",
        }),
      ),
    );
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it("opens empty for Add after an edit was closed", async () => {
    const props = { zoneName, onOpenChange: vi.fn(), onSuccess: vi.fn() };
    const { rerender } = render(<DNSRecordForm {...props} open record={mxRecord} />);
    await waitFor(() => expect(textbox("Name").value).toBe("mail"));

    rerender(<DNSRecordForm {...props} open={false} record={undefined} />);
    rerender(<DNSRecordForm {...props} open record={undefined} />);

    await waitFor(() => expect(textbox("Name").value).toBe(""));
    expect(textbox("Value").value).toBe("");
    expect(screen.getByRole("heading", { name: "Add DNS Record" })).toBeTruthy();
  });

  it("withholds Create with the server's reason when POST /api/v1/dns/zones/{zone}/records is not offered", async () => {
    off.add(CREATE_OP);
    render(
      <DNSRecordForm zoneName={zoneName} open onOpenChange={vi.fn()} onSuccess={vi.fn()} />,
    );

    fireEvent.change(textbox("Name"), { target: { value: "www" } });
    fireEvent.change(textbox("Value"), { target: { value: "www-target" } });
    const button = screen.getByRole("button", { name: "Create" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.getAttribute("title")).toBe("not-configured: dns");
    expect(button.getAttribute("data-capability-op")).toBe(CREATE_OP);
    expect(button.getAttribute("data-capability-enabled")).toBe("false");

    fireEvent.click(button);
    fireEvent.submit(button.closest("form") as HTMLFormElement);
    await new Promise((r) => setTimeout(r, 0));
    expect(dns.addRecord).not.toHaveBeenCalled();
  });

  it("withholds Update when PUT /api/v1/dns/zones/{zone}/records is not offered", async () => {
    off.add(UPDATE_OP);
    render(
      <DNSRecordForm
        zoneName={zoneName}
        open
        onOpenChange={vi.fn()}
        onSuccess={vi.fn()}
        record={mxRecord}
      />,
    );

    fireEvent.change(textbox("Value"), { target: { value: "mx2.example.com." } });
    const button = screen.getByRole("button", { name: "Update" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.getAttribute("data-capability-op")).toBe(UPDATE_OP);

    fireEvent.click(button);
    fireEvent.submit(button.closest("form") as HTMLFormElement);
    await new Promise((r) => setTimeout(r, 0));
    expect(dns.updateRecord).not.toHaveBeenCalled();
  });

  it("gates Create on POST and Update on PUT when the server offers both", () => {
    render(
      <DNSRecordForm zoneName={zoneName} open onOpenChange={vi.fn()} onSuccess={vi.fn()} />,
    );
    const create = screen.getByRole("button", { name: "Create" });
    expect(create.getAttribute("data-capability-op")).toBe(CREATE_OP);
    expect(create.getAttribute("data-capability-enabled")).toBe("true");

    cleanup();
    render(
      <DNSRecordForm
        zoneName={zoneName}
        open
        onOpenChange={vi.fn()}
        onSuccess={vi.fn()}
        record={mxRecord}
      />,
    );
    const update = screen.getByRole("button", { name: "Update" });
    expect(update.getAttribute("data-capability-op")).toBe(UPDATE_OP);
    expect(update.getAttribute("data-capability-enabled")).toBe("true");
  });

  it("keeps Update enabled when only POST is withheld", () => {
    off.add(CREATE_OP);
    render(
      <DNSRecordForm
        zoneName={zoneName}
        open
        onOpenChange={vi.fn()}
        onSuccess={vi.fn()}
        record={mxRecord}
      />,
    );
    const update = screen.getByRole("button", { name: "Update" }) as HTMLButtonElement;
    expect(update.disabled).toBe(false);
    expect(update.getAttribute("data-capability-enabled")).toBe("true");
  });
});
