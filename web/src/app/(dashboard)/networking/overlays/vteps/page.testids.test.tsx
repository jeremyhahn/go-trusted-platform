import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import OverlayVtepsPage from "./page";

// #2059: the real-server spec (test/integration/web/overlay.spec.ts) finds each
// section and table of the VTEPs page by its test id. These tests pin those ids
// on the real SDK client with fetch stubbed, the boundary the browser crosses.

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

const base = "/api/v1/overlay";

/** Answers every overlay read and the two deletes. */
function routes() {
  return (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
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

describe("OverlayVtepsPage test ids", () => {
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

  beforeEach(() => {
    fetchMock.mockImplementation(routes());
  });

  afterEach(() => {
    cleanup();
    fetchMock.mockReset();
  });

  it("each section carries its test id", async () => {
    renderPage();

    expect(await screen.findByText("tenant-blue")).toBeTruthy();
    for (const id of [
      "overlay-vteps",
      "overlay-vnis",
      "overlay-tunnels",
      "overlay-macs",
      "overlay-forget-mac",
    ]) {
      expect(screen.getByTestId(id)).toBeTruthy();
    }
  });

  it("the tunnel row and its Stats button sit in tunnels-table", async () => {
    renderPage();

    expect(await screen.findByRole("button", { name: "Stats node-b 5001" })).toBeTruthy();
    const table = screen.getByTestId("tunnels-table");
    expect(within(table).getByRole("button", { name: "Stats node-b 5001" })).toBeTruthy();
  });

  it("the remote MAC row sits in macs-table and the VNI row in vnis-table", async () => {
    renderPage();

    expect(await screen.findByText("aa:bb:cc:dd:ee:ff")).toBeTruthy();
    expect(within(screen.getByTestId("macs-table")).getByText("aa:bb:cc:dd:ee:ff")).toBeTruthy();
    expect(await screen.findByText("tenant-blue")).toBeTruthy();
    expect(within(screen.getByTestId("vnis-table")).getByText("tenant-blue")).toBeTruthy();
  });
});
