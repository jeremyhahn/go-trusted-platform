import * as React from "react";
import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import { useOverlayVteps } from "./use-overlay-vteps";

// #2059: the VTEPs page hook reads and writes the overlay through
// client.overlay (the SDK's REST routes under /api/v1/overlay). These tests
// stub fetch, the boundary the browser crosses, with protojson envelopes.

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

const status = {
  nodeId: "node-a",
  vtepIp: "10.0.0.1",
  vtepCount: 2,
  vniCount: 1,
  tunnelCount: 1,
  remoteMacCount: 1,
  healthy: true,
  vxlanPort: 4789,
  underlayMtu: 1500,
};
const vtepA = { nodeId: "node-a", ip: "10.0.0.1", healthy: true, lastSeen: "2026-11-21T10:00:00Z" };
const vtepB = { nodeId: "node-b", ip: "10.0.0.2", healthy: false, lastSeen: "2026-11-21T09:59:00Z" };
const vni = {
  id: "vni-5001",
  config: { vni: 5001, name: "tenant-blue" },
  createdAt: "2026-11-21T09:00:00Z",
  macCount: 1,
};
const tunnel = {
  localVtep: "node-a",
  remoteVtep: "node-b",
  vni: 5001,
  state: "up",
  bytesTx: "4096",
  bytesRx: "8192",
};
const mac = {
  mac: "aa:bb:cc:dd:ee:ff",
  vni: 5001,
  remoteVtep: "node-b",
  learnedAt: "2026-11-21T09:30:00Z",
};

type Route = (method: string, url: URL) => Response | undefined;

const base = "/api/v1/overlay";

/** Answers every overlay read and the two deletes, then defers to `extra` first. */
function overlayRoutes(extra: Route = () => undefined) {
  return (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const answer = extra(method, url);
    if (answer) {
      return Promise.resolve(answer);
    }
    const key = `${method} ${url.pathname}`;
    switch (key) {
      case `GET ${base}/status`:
        return Promise.resolve(ok({ status }));
      case `GET ${base}/vteps`:
        return Promise.resolve(ok({ vteps: [vtepA, vtepB] }));
      case `GET ${base}/vteps/node-a`:
        return Promise.resolve(ok({ vtep: vtepA }));
      case `GET ${base}/vnis`:
        return Promise.resolve(ok({ vnis: [vni] }));
      case `GET ${base}/tunnels`:
        return Promise.resolve(ok({ tunnels: [tunnel] }));
      case `GET ${base}/tunnels/stats`:
        return Promise.resolve(ok({ tunnel }));
      case `GET ${base}/macs`:
        return Promise.resolve(ok({ macs: [mac] }));
      case `DELETE ${base}/vnis/5001`:
      case `DELETE ${base}/macs`:
        return Promise.resolve(ok({ status: { success: true, message: "" } }));
      default:
        return Promise.resolve(failure(404, `no route ${key}`));
    }
  };
}

describe("useOverlayVteps", () => {
  const fetchMock = vi.fn<typeof fetch>();

  function renderOverlay() {
    const client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: fetchMock,
      retry: { maxRetries: 0 },
    });
    const wrapper = ({ children }: { children: React.ReactNode }) => (
      // The SDK builds against its own @types/react, whose ReactNode has no bigint.
      <PlatformProvider client={client}>{children as React.ComponentProps<typeof PlatformProvider>["children"]}</PlatformProvider>
    );
    return renderHook(() => useOverlayVteps(), { wrapper });
  }

  /** The calls fetch saw for one method and path. */
  function callsTo(method: string, path: string) {
    return fetchMock.mock.calls.filter(([input, init]) => {
      return (init?.method ?? "GET") === method && new URL(String(input)).pathname === path;
    });
  }

  beforeEach(() => {
    fetchMock.mockReset();
  });

  it("lists VTEPs, VNIs, tunnels and remote MACs through client.overlay", async () => {
    fetchMock.mockImplementation(overlayRoutes());
    const { result } = renderOverlay();

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.vteps).toHaveLength(2);
    expect(result.current.vnis).toHaveLength(1);
    expect(result.current.tunnels).toHaveLength(1);
    expect(result.current.macs).toHaveLength(1);
    expect(callsTo("GET", `${base}/vteps`)).toHaveLength(1);
    expect(callsTo("GET", `${base}/vnis`)).toHaveLength(1);
    expect(callsTo("GET", `${base}/tunnels`)).toHaveLength(1);
    expect(callsTo("GET", `${base}/macs`)).toHaveLength(1);
  });

  it("reads the overlay status through client.overlay.getStatus", async () => {
    fetchMock.mockImplementation(overlayRoutes());
    const { result } = renderOverlay();

    await waitFor(() => expect(result.current.status?.vtepIp).toBe("10.0.0.1"));
    expect(result.current.status?.vxlanPort).toBe(4789);
    expect(callsTo("GET", `${base}/status`)).toHaveLength(1);
  });

  it("getVTEP and getTunnelStats return the one item", async () => {
    fetchMock.mockImplementation(overlayRoutes());
    const { result } = renderOverlay();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    const v = await result.current.getVTEP("node-a");
    expect(v?.nodeId).toBe("node-a");

    const t = await result.current.getTunnelStats("node-b", 5001);
    expect(t?.remoteVtep).toBe("node-b");
    const [call] = callsTo("GET", `${base}/tunnels/stats`);
    expect(new URL(String(call?.[0])).search).toBe("?remote_vtep=node-b&vni=5001");
  });

  it("deleteVNI deletes then re-reads the VNIs and MACs", async () => {
    fetchMock.mockImplementation(overlayRoutes());
    const { result } = renderOverlay();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await act(() => result.current.deleteVNI(5001));

    await waitFor(() => expect(callsTo("DELETE", `${base}/vnis/5001`)).toHaveLength(1));
    await waitFor(() => expect(callsTo("GET", `${base}/vnis`).length).toBeGreaterThanOrEqual(2));
    expect(callsTo("GET", `${base}/macs`).length).toBeGreaterThanOrEqual(2);
  });

  it("forgetMAC sends mac and vni and re-reads the MACs", async () => {
    fetchMock.mockImplementation(overlayRoutes());
    const { result } = renderOverlay();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await act(() => result.current.forgetMAC("aa:bb:cc:dd:ee:ff", 5001));

    const calls = callsTo("DELETE", `${base}/macs`);
    expect(calls).toHaveLength(1);
    const params = new URL(String(calls[0]?.[0])).searchParams;
    expect(params.get("mac")).toBe("aa:bb:cc:dd:ee:ff");
    expect(params.get("vni")).toBe("5001");
    await waitFor(() => expect(callsTo("GET", `${base}/macs`).length).toBeGreaterThanOrEqual(2));
  });

  it("a refused write rejects with the server message", async () => {
    fetchMock.mockImplementation(
      overlayRoutes((method, url) =>
        method === "DELETE" && url.pathname === `${base}/vnis/5001` ? failure(409, "vni in use") : undefined
      )
    );
    const { result } = renderOverlay();
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await expect(result.current.deleteVNI(5001)).rejects.toThrow("vni in use");
  });

  it("a list failure surfaces as that list's error", async () => {
    fetchMock.mockImplementation(
      overlayRoutes((method, url) =>
        method === "GET" && url.pathname === `${base}/tunnels`
          ? failure(503, "overlay controller not configured")
          : undefined
      )
    );
    const { result } = renderOverlay();

    await waitFor(() => expect(result.current.tunnelsError).toBeTruthy());
    await waitFor(() => expect(result.current.vteps).toHaveLength(2));
  });
});
