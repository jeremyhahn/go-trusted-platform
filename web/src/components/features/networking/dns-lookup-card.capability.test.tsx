import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The DNS lookup card gates Resolve and Register on the server's
// capabilities (#2060); the capability hook and the lookup hook are mocked.

type Lookup = {
  resolve: ReturnType<typeof vi.fn>;
  register: ReturnType<typeof vi.fn>;
  isResolving: boolean;
  isRegistering: boolean;
};

const { lookup, toast, off } = vi.hoisted(() => ({
  lookup: {} as Lookup,
  toast: vi.fn(),
  off: new Set<string>(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useToast: () => ({ toast }),
}));

vi.mock("@/hooks/use-dns-lookup", () => ({
  useDNSLookup: () => lookup,
}));

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: "not-configured: dns" } : { enabled: true },
  }),
}));

import { DNSLookupCard } from "./dns-lookup-card";

const RESOLVE_OP = "GET /api/v1/dns/resolve";
const REGISTER_OP = "POST /api/v1/dns/register";

const button = (name: string) => screen.getByRole("button", { name }) as HTMLButtonElement;
const input = (label: string) => screen.getByLabelText(label) as HTMLInputElement;

function fillInputs() {
  fireEvent.change(input("Name"), { target: { value: "www.example.com." } });
  fireEvent.change(input("Host name"), { target: { value: "host1.example.com." } });
  fireEvent.change(input("IP address"), { target: { value: "192.0.2.10" } });
}

beforeEach(() => {
  lookup.resolve = vi.fn().mockResolvedValue({ records: [], authoritative: true });
  lookup.register = vi.fn().mockResolvedValue({ status: "registered", zone: "example.com." });
  lookup.isResolving = false;
  lookup.isRegistering = false;
  toast.mockReset();
});

afterEach(() => {
  cleanup();
  off.clear();
});

describe("DNSLookupCard capability gate", () => {
  it("withholds Resolve with the server's reason when GET /api/v1/dns/resolve is not offered", () => {
    off.add(RESOLVE_OP);
    render(<DNSLookupCard onRegistered={vi.fn()} />);
    fillInputs();

    const el = button("Resolve");
    expect(el.getAttribute("data-capability-op")).toBe(RESOLVE_OP);
    expect(el.getAttribute("data-capability-enabled")).toBe("false");
    expect(el.disabled).toBe(true);
    expect(el.getAttribute("title")).toBe("not-configured: dns");

    fireEvent.click(el);
    expect(lookup.resolve).not.toHaveBeenCalled();
    expect(button("Register").getAttribute("data-capability-enabled")).toBe("true");
  });

  it("withholds Register with the server's reason when POST /api/v1/dns/register is not offered", () => {
    off.add(REGISTER_OP);
    const onRegistered = vi.fn();
    render(<DNSLookupCard onRegistered={onRegistered} />);
    fillInputs();

    const el = button("Register");
    expect(el.getAttribute("data-capability-op")).toBe(REGISTER_OP);
    expect(el.getAttribute("data-capability-enabled")).toBe("false");
    expect(el.disabled).toBe(true);
    expect(el.getAttribute("title")).toBe("not-configured: dns");

    fireEvent.click(el);
    expect(lookup.register).not.toHaveBeenCalled();
    expect(onRegistered).not.toHaveBeenCalled();
    expect(button("Resolve").getAttribute("data-capability-enabled")).toBe("true");
  });

  it("leaves both enabled when the server offers them", () => {
    render(<DNSLookupCard onRegistered={vi.fn()} />);
    fillInputs();

    for (const [name, op] of [
      ["Resolve", RESOLVE_OP],
      ["Register", REGISTER_OP],
    ] as const) {
      const el = button(name);
      expect(el.getAttribute("data-capability-op")).toBe(op);
      expect(el.getAttribute("data-capability-enabled")).toBe("true");
      expect(el.disabled).toBe(false);
    }
  });
});
