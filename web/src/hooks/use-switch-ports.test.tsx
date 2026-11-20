import * as React from "react";
import { act, cleanup, renderHook as baseRenderHook, waitFor } from "@testing-library/react";
import { PlatformProvider } from "trusted-platform-sdk";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useSwitchPorts } from "./use-switch-ports";

/**
 * useSwitchPorts drives the five SwitchService REST routes
 * (pkg/webservice/v1/rest/switch/router.go) and reports the server's
 * structured 503 as "unavailable", the capability its page gates on (#2066).
 */

const PORTS = [
  { port: "Eth1/1", mode: "access", access_vlan: 10, enabled: true, link_up: true },
  { port: "Eth1/2", mode: "trunk", access_vlan: 1, enabled: false, link_up: false },
];

type FetchCall = { url: string; init?: RequestInit };
type Responder = (url: string, init?: RequestInit) => Response;

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const NOT_CONFIGURED = {
  code: 503,
  success: false,
  error: "switch service not configured by daemon — REST surface is dark",
  service: "switch",
  reason: "SERVICE_NOT_CONFIGURED",
};

const ok: Responder = (url, init) => {
  const method = init?.method ?? "GET";
  if (method !== "GET") {
    return json(200, { success: true, payload: { success: true } });
  }
  if (url.endsWith("/ports")) {
    return json(200, { success: true, payload: PORTS });
  }
  return json(200, { success: true, payload: PORTS[0] });
};

let calls: FetchCall[];
let respond: Responder;

const fetchStub = vi.fn(async (url: string, init?: RequestInit) => {
  calls.push({ url: String(url), init });
  return respond(String(url), init);
}) as unknown as typeof fetch;

// The SDK resolves its own @types/react: view its provider through the web's.
const Provider = PlatformProvider as unknown as React.ComponentType<{
  config: Record<string, unknown>;
  children: React.ReactNode;
}>;

function wrapper({ children }: { children: React.ReactNode }) {
  return (
    <Provider config={{ baseUrl: "/api", fetch: fetchStub, retry: { maxRetries: 0 } }}>
      {children}
    </Provider>
  );
}

function renderHook<T>(hook: () => T) {
  return baseRenderHook(hook, { wrapper });
}

describe("useSwitchPorts", () => {
  beforeEach(() => {
    calls = [];
    respond = ok;
  });

  afterEach(() => {
    cleanup();
  });

  it("lists the ports and reports the service available", async () => {
    const { result } = renderHook(() => useSwitchPorts("core-1"));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.ports.map((p) => p.port)).toEqual(["Eth1/1", "Eth1/2"]);
    expect(result.current.unavailable).toBe(false);
    expect(result.current.unavailableReason).toBeUndefined();
    expect(calls[0].url).toBe("/api/v1/switches/core-1/ports");
  });

  it("the server's structured 503 marks the switch service unavailable with its reason", async () => {
    respond = () => json(503, NOT_CONFIGURED);
    const { result } = renderHook(() => useSwitchPorts("core-1"));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.unavailable).toBe(true);
    expect(result.current.unavailableReason).toContain("switch service not configured");
    expect(result.current.ports).toEqual([]);
  });

  it("another failure is an error, not an unavailable service", async () => {
    respond = () => json(502, { success: false, error: "switch unreachable" });
    const { result } = renderHook(() => useSwitchPorts("core-1"));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.unavailable).toBe(false);
    expect(result.current.error).toBeDefined();
  });

  it("each action calls its route with the encoded port", async () => {
    const { result } = renderHook(() => useSwitchPorts("core-1"));
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await act(async () => {
      await result.current.getPortStatus("Eth1/1");
      await result.current.enablePort("Eth1/1");
      await result.current.disablePort("Eth1/1");
      await result.current.setPortVLAN("Eth1/1", 20);
    });

    const after = calls.slice(1).map((c) => `${c.init?.method ?? "GET"} ${c.url}`);
    expect(after).toEqual([
      "GET /api/v1/switches/core-1/ports/Eth1%2F1",
      "POST /api/v1/switches/core-1/ports/Eth1%2F1/enable",
      "POST /api/v1/switches/core-1/ports/Eth1%2F1/disable",
      "POST /api/v1/switches/core-1/ports/Eth1%2F1/vlan",
    ]);
    const vlan = calls.find((c) => c.url.endsWith("/vlan"));
    expect(vlan?.init?.body).toBe('{"vlan_id":20}');
  });

  it("a failed action throws the server's message", async () => {
    const { result } = renderHook(() => useSwitchPorts("core-1"));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    respond = () => json(500, { success: false, error: "port is locked" });
    await expect(result.current.enablePort("Eth1/1")).rejects.toThrow("port is locked");
  });
});
