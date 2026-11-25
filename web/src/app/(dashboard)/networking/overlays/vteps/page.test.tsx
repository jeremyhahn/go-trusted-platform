import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import OverlayVtepsPage from "./page";
const auth: { current: { user: { roles: string[] } } | null } = { current: { user: { roles: ["admin"] } } };
vi.mock("@/contexts/AuthContext", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/contexts/AuthContext")>()), useOptionalAuth: () => auth.current }));

// #2059: the VTEPs page drives the overlay through client.overlay (the SDK's
// REST routes under /api/v1/overlay). These tests stub fetch, the boundary
// the browser crosses, with the protojson envelopes the webservice writes.

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

/** Answers every overlay read and the two deletes, consulting `extra` first. */
function routes(extra: Route = () => undefined) {
  return (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const answer = extra(method, url);
    if (answer) {
      return Promise.resolve(answer);
    }
    const key = `${method} ${url.pathname}`;
    switch (key) {
      case `GET /api/v1/capabilities`:
        // #2059: the destructive controls sit in the capability gate, which
        // fails closed; this server offers every overlay op.
        return Promise.resolve(
          ok({
            capabilities: [`DELETE ${base}/vnis/{vni:[0-9]+}`, `DELETE ${base}/macs`].map((op) => ({ op, kind: "route", enabled: true })),
            total: 2,
            enabled: 2,
          })
        );
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

/** Answers the status reads in order: the first read gets bodies[0], each later read the next body, the last one repeating. */
function statusReads(...bodies: Array<typeof status>): Route {
  let n = 0;
  return (method, url) =>
    method === "GET" && url.pathname === `${base}/status`
      ? ok({ status: bodies[Math.min(n++, bodies.length - 1)] })
      : undefined;
}

describe("OverlayVtepsPage", () => {
  const fetchMock = vi.fn<typeof fetch>();

  function renderPage() {
    const client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: fetchMock,
      retry: { maxRetries: 0 },
    });
    return render(
      <PlatformProvider client={client}>
        <OverlayVtepsPage />
      </PlatformProvider>
    );
  }

  /** The calls fetch saw for one method and path. */
  function callsTo(method: string, path: string) {
    return fetchMock.mock.calls.filter(([input, init]) => {
      return (init?.method ?? "GET") === method && new URL(String(input)).pathname === path;
    });
  }

  /** The named control once the capability gate has opened it (#2059). */
  async function openControl(name: string) {
    const control = await screen.findByRole("button", { name });
    await waitFor(() => expect((control as HTMLButtonElement).disabled).toBe(false));
    return control;
  }

  beforeEach(() => {
    fetchMock.mockReset();
    auth.current = { user: { roles: ["admin"] } };
  });

  afterEach(() => {
    cleanup();
  });

  it("lists the VTEPs, VNIs, tunnels and remote MACs", async () => {
    fetchMock.mockImplementation(routes());
    renderPage();

    const table = screen.getByTestId("vteps-table");
    expect(await within(table).findByText("node-b")).toBeTruthy();
    expect(await screen.findByText("tenant-blue")).toBeTruthy();
    expect(await screen.findByText("aa:bb:cc:dd:ee:ff")).toBeTruthy();
  });

  it("shows the overlay status card", async () => {
    fetchMock.mockImplementation(routes());
    renderPage();

    const card = await screen.findByTestId("overlay-status");
    await waitFor(() => expect(card.textContent).toContain("10.0.0.1"));
    expect(card.textContent).toContain("4789");
    expect(card.textContent).toContain("1500");
    expect(card.textContent).toContain("healthy");
  });

  it("shows the status error and still lists VTEPs", async () => {
    fetchMock.mockImplementation(
      routes((method, url) =>
        method === "GET" && url.pathname === `${base}/status`
          ? failure(503, "overlay controller not configured")
          : undefined
      )
    );
    renderPage();

    const err = await screen.findByTestId("overlay-status-error");
    expect(err.textContent).toContain("overlay controller not configured");
    expect(await within(screen.getByTestId("vteps-table")).findByText("node-a")).toBeTruthy();
  });

  it("Details opens the VTEP dialog", async () => {
    fetchMock.mockImplementation(routes());
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: "Details node-a" }));
    expect(await screen.findByText("VTEP node-a")).toBeTruthy();
  });

  it("Stats opens the tunnel statistics dialog", async () => {
    fetchMock.mockImplementation(routes());
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: "Stats node-b 5001" }));
    expect(await screen.findByText("Tunnel statistics")).toBeTruthy();
    expect(await screen.findByText("8192")).toBeTruthy();
  });

  it("Delete VNI confirms then deletes", async () => {
    fetchMock.mockImplementation(routes());
    renderPage();

    fireEvent.click(await openControl("Delete VNI 5001"));
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));

    await waitFor(() => expect(callsTo("DELETE", `${base}/vnis/5001`)).toHaveLength(1));
  });

  it("Forget on a MAC row confirms then forgets", async () => {
    fetchMock.mockImplementation(routes());
    renderPage();

    fireEvent.click(await openControl("Forget aa:bb:cc:dd:ee:ff on VNI 5001"));
    fireEvent.click(await screen.findByRole("button", { name: "Forget" }));

    await waitFor(() => expect(callsTo("DELETE", `${base}/macs`)).toHaveLength(1));
    const [call] = callsTo("DELETE", `${base}/macs`);
    const params = new URL(String(call?.[0])).searchParams;
    expect(params.get("mac")).toBe("aa:bb:cc:dd:ee:ff");
    expect(params.get("vni")).toBe("5001");
  });

  it("Delete VNI shows the re-read status counts", async () => {
    fetchMock.mockImplementation(routes(statusReads(status, { ...status, vniCount: 0, remoteMacCount: 0 })));
    renderPage();

    await waitFor(() => expect(screen.getByTestId("overlay-status").textContent).toContain("VNI count1"));
    fireEvent.click(await openControl("Delete VNI 5001"));
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));

    await waitFor(() => {
      const text = screen.getByTestId("overlay-status").textContent;
      expect(text).toContain("VNI count0");
      expect(text).toContain("Remote MAC count0");
    });
    expect(callsTo("GET", `${base}/status`)).toHaveLength(2);
  });

  it("Refresh re-reads the status", async () => {
    fetchMock.mockImplementation(routes(statusReads(status, { ...status, vtepCount: 3 })));
    renderPage();

    await waitFor(() => expect(screen.getByTestId("overlay-status").textContent).toContain("VTEP count2"));
    const refresh = screen.getByRole("button", { name: "Refresh" });
    await waitFor(() => expect((refresh as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(refresh);

    await waitFor(() => expect(screen.getByTestId("overlay-status").textContent).toContain("VTEP count3"));
    expect(callsTo("GET", `${base}/status`)).toHaveLength(2);
  });
});
