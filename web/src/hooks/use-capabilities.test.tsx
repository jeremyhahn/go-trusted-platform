import type { ReactNode } from "react";
import { cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import { useCapabilities } from "./use-capabilities";

// #2058 / #2033 item 4: the capability gate reads GET /api/v1/capabilities
// once per client and fails closed.

// The SDK's PlatformProvider types its children with the SDK's own React types.
type ProviderChildren = Parameters<typeof PlatformProvider>[0]["children"];

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function ok(payload: unknown): Response {
  return jsonResponse(200, { code: 200, error: "", success: true, payload });
}

function failure(status: number, error: string): Response {
  return jsonResponse(status, { code: status, error, success: false });
}

const capabilities = {
  capabilities: [
    { op: "POST /api/v1/ntp/step", kind: "route", enabled: true },
    { op: "GET /api/v1/ntp/sources", kind: "route", enabled: false, reason: "blocked: integration" },
  ],
  total: 2,
  enabled: 1,
};

describe("useCapabilities", () => {
  const fetchMock = vi.fn<typeof fetch>();
  let client: PlatformClient;

  function wrapper({ children }: { children: ReactNode }) {
    return <PlatformProvider client={client}>{children as ProviderChildren}</PlatformProvider>;
  }

  function capabilityCalls() {
    return fetchMock.mock.calls.filter(([input, init]) => {
      return (
        (init?.method ?? "GET") === "GET" &&
        new URL(String(input)).pathname === "/api/v1/capabilities"
      );
    });
  }

  beforeEach(() => {
    fetchMock.mockReset();
    client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: fetchMock,
      retry: { maxRetries: 0 },
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("while loading every op is disabled", () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => undefined));

    const { result } = renderHook(() => useCapabilities(), { wrapper });

    expect(result.current.loading).toBe(true);
    expect(result.current.capability("POST /api/v1/ntp/step")).toEqual({
      enabled: false,
      reason: "checking server capabilities",
    });
  });

  it("a listed enabled op is enabled", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(ok(capabilities)));

    const { result } = renderHook(() => useCapabilities(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.capability("POST /api/v1/ntp/step").enabled).toBe(true);
  });

  it("a listed disabled op carries the server reason", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(ok(capabilities)));

    const { result } = renderHook(() => useCapabilities(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.capability("GET /api/v1/ntp/sources")).toEqual({
      enabled: false,
      reason: "blocked: integration",
    });
  });

  it("an unlisted op is disabled as not offered by this server", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(ok(capabilities)));

    const { result } = renderHook(() => useCapabilities(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.capability("GET /api/v1/ntp/status")).toEqual({
      enabled: false,
      reason: "not offered by this server",
    });
  });

  it("a fetch error disables every op", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(failure(500, "boom")));

    const { result } = renderHook(() => useCapabilities(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBeTruthy();
    expect(result.current.capability("POST /api/v1/ntp/step")).toEqual({
      enabled: false,
      reason: "server capabilities unavailable",
    });
  });

  it("two hooks on one client fetch capabilities once", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(ok(capabilities)));

    const first = renderHook(() => useCapabilities(), { wrapper });
    const second = renderHook(() => useCapabilities(), { wrapper });

    await waitFor(() => expect(first.result.current.loading).toBe(false));
    await waitFor(() => expect(second.result.current.loading).toBe(false));
    expect(second.result.current.capability("POST /api/v1/ntp/step").enabled).toBe(true);
    expect(capabilityCalls()).toHaveLength(1);
  });
});
