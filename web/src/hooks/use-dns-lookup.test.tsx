import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2060: useDNSLookup resolves a name through client.dns.resolve and registers
// a name through client.dns.register (the SDK service is the network boundary,
// mocked here through the @/hooks useDNS re-export).

const { dns } = vi.hoisted(() => ({
  dns: { resolve: vi.fn(), register: vi.fn() },
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useDNS: () => dns,
}));

import { useDNSLookup } from "./use-dns-lookup";

beforeEach(() => {
  dns.resolve.mockReset();
  dns.register.mockReset();
});

afterEach(() => {
  cleanup();
});

describe("useDNSLookup", () => {
  it("resolves a name through client.dns.resolve", async () => {
    const data = {
      records: [{ type: "RECORD_TYPE_A", a: { name: "www.example.com.", value: "10.0.0.5", ttl: 300 } }],
      authoritative: true,
    };
    dns.resolve.mockResolvedValue({ success: true, data });
    const { result } = renderHook(() => useDNSLookup());

    let res: unknown;
    await act(async () => {
      res = await result.current.resolve({ fqdn: "www.example.com.", type: "A" });
    });

    expect(res).toEqual(data);
    expect(dns.resolve).toHaveBeenCalledTimes(1);
    expect(dns.resolve).toHaveBeenCalledWith({ fqdn: "www.example.com.", type: "A" });
  });

  it("rejects a refused resolve with the server message", async () => {
    dns.resolve.mockResolvedValue({ success: false, error: { code: "INVALID_ARGUMENT", message: "invalid record type" } });
    const { result } = renderHook(() => useDNSLookup());

    await act(async () => {
      await expect(result.current.resolve({ fqdn: "www.example.com.", type: "A" })).rejects.toMatchObject({
        message: "invalid record type",
      });
    });
  });

  it("registers a name through client.dns.register", async () => {
    const data = { status: "registered", zone: "example.com." };
    dns.register.mockResolvedValue({ success: true, data });
    const { result } = renderHook(() => useDNSLookup());

    let res: unknown;
    await act(async () => {
      res = await result.current.register({ fqdn: "host1.example.com.", ip: "10.0.0.10" });
    });

    expect(res).toEqual(data);
    expect(dns.register).toHaveBeenCalledTimes(1);
    expect(dns.register).toHaveBeenCalledWith({ fqdn: "host1.example.com.", ip: "10.0.0.10" });
  });

  it("rejects a refused register with the server message", async () => {
    dns.register.mockResolvedValue({
      success: false,
      error: { code: "NOT_FOUND", message: "no zone for host1.example.com." },
    });
    const { result } = renderHook(() => useDNSLookup());

    await act(async () => {
      await expect(result.current.register({ fqdn: "host1.example.com.", ip: "10.0.0.10" })).rejects.toMatchObject({
        message: "no zone for host1.example.com.",
      });
    });
  });
});
