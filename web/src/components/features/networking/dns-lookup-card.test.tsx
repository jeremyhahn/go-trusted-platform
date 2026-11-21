import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2060: the zones page's Resolve and register card drives useDNSLookup (the
// hook is mocked here; its own test covers the client.dns calls).

type Lookup = {
  resolve: ReturnType<typeof vi.fn>;
  register: ReturnType<typeof vi.fn>;
  isResolving: boolean;
  isRegistering: boolean;
};

const { lookup, toast } = vi.hoisted(() => ({
  lookup: {} as Lookup,
  toast: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useToast: () => ({ toast }),
}));

vi.mock("@/hooks/use-dns-lookup", () => ({
  useDNSLookup: () => lookup,
}));

import { DNSLookupCard } from "./dns-lookup-card";

function button(name: string): HTMLButtonElement {
  return screen.getByRole("button", { name }) as HTMLButtonElement;
}

function input(label: string): HTMLInputElement {
  return screen.getByLabelText(label) as HTMLInputElement;
}

beforeEach(() => {
  lookup.resolve = vi.fn();
  lookup.register = vi.fn();
  lookup.isResolving = false;
  lookup.isRegistering = false;
  toast.mockReset();
});

afterEach(() => {
  cleanup();
});

describe("DNSLookupCard", () => {
  it("Resolve and Register are disabled until their inputs are filled", () => {
    render(<DNSLookupCard />);
    expect(button("Resolve").disabled).toBe(true);
    expect(button("Register").disabled).toBe(true);

    fireEvent.change(input("Name"), { target: { value: "www.example.com." } });
    expect(button("Resolve").disabled).toBe(false);

    fireEvent.change(input("Host name"), { target: { value: "host1.example.com." } });
    expect(button("Register").disabled).toBe(true);
    fireEvent.change(input("IP address"), { target: { value: "10.0.0.10" } });
    expect(button("Register").disabled).toBe(false);
  });

  it("resolves and lists the records with the authoritative badge", async () => {
    lookup.resolve.mockResolvedValue({
      records: [
        { type: "RECORD_TYPE_A", a: { name: "www.example.com.", value: "10.0.0.5" } },
        { type: "RECORD_TYPE_MX", mx: { name: "example.com.", value: "mail.example.com." } },
      ],
      authoritative: true,
    });
    render(<DNSLookupCard />);

    fireEvent.change(input("Name"), { target: { value: "www.example.com." } });
    fireEvent.change(input("Type"), { target: { value: "MX" } });
    fireEvent.click(button("Resolve"));

    const rows = await screen.findAllByTestId("dns-resolve-record");
    expect(lookup.resolve).toHaveBeenCalledWith({ fqdn: "www.example.com.", type: "MX" });
    expect(rows.map((r) => r.textContent)).toEqual([
      "A www.example.com. 10.0.0.5",
      "MX example.com. mail.example.com.",
    ]);
    expect(screen.getByTestId("dns-resolve-authoritative").textContent).toBe("Authoritative");
  });

  it("shows No records for a non-authoritative empty answer", async () => {
    lookup.resolve.mockResolvedValue({ records: [], authoritative: false });
    render(<DNSLookupCard />);

    fireEvent.change(input("Name"), { target: { value: "unknown.test." } });
    fireEvent.click(button("Resolve"));

    expect((await screen.findByTestId("dns-resolve-empty")).textContent).toBe("No records");
    expect(screen.getByTestId("dns-resolve-authoritative").textContent).toBe("Not authoritative");
    expect(screen.queryByTestId("dns-resolve-record")).toBeNull();
  });

  it("shows the resolve error", async () => {
    lookup.resolve.mockRejectedValue({ message: "invalid record type" });
    render(<DNSLookupCard />);

    fireEvent.change(input("Name"), { target: { value: "www.example.com." } });
    fireEvent.click(button("Resolve"));

    expect((await screen.findByTestId("dns-resolve-error")).textContent).toBe("Resolve failed: invalid record type");
    expect(screen.queryByTestId("dns-resolve-authoritative")).toBeNull();
  });

  it("registers a name, toasts and calls onRegistered", async () => {
    lookup.register.mockResolvedValue({ status: "registered", zone: "example.com." });
    const onRegistered = vi.fn();
    render(<DNSLookupCard onRegistered={onRegistered} />);

    fireEvent.change(input("Host name"), { target: { value: "host1.example.com." } });
    fireEvent.change(input("IP address"), { target: { value: "10.0.0.10" } });
    fireEvent.click(button("Register"));

    expect(lookup.register).toHaveBeenCalledWith({ fqdn: "host1.example.com.", ip: "10.0.0.10" });
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Registered", variant: "success" }))
    );
    expect(onRegistered).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(input("Host name").value).toBe(""));
    expect(input("IP address").value).toBe("");
  });

  it("toasts a refused register and keeps the inputs", async () => {
    lookup.register.mockRejectedValue({ message: "no zone for host1.example.com." });
    const onRegistered = vi.fn();
    render(<DNSLookupCard onRegistered={onRegistered} />);

    fireEvent.change(input("Host name"), { target: { value: "host1.example.com." } });
    fireEvent.change(input("IP address"), { target: { value: "10.0.0.10" } });
    fireEvent.click(button("Register"));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: "Failed to register",
          description: "no zone for host1.example.com.",
          variant: "destructive",
        })
      )
    );
    expect(onRegistered).not.toHaveBeenCalled();
    expect(input("Host name").value).toBe("host1.example.com.");
    expect(input("IP address").value).toBe("10.0.0.10");
  });
});
