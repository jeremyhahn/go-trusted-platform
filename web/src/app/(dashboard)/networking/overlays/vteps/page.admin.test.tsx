import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import OverlayVtepsPage from "./page";
const auth: { current: { user: { roles: string[] } } | null } = { current: { user: { roles: ["admin"] } } };
vi.mock("@/contexts/AuthContext", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/contexts/AuthContext")>()), useOptionalAuth: () => auth.current }));

// #2059: every overlay route is mounted behind the admin role on the server,
// so the page disables Delete VNI and both Forget MAC controls for a session
// without that role and says why, instead of failing after the confirm.

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

const destructive = ["Delete VNI 5001", "Forget aa:bb:cc:dd:ee:ff on VNI 5001", "Forget MAC"];

describe("OverlayVtepsPage admin gate (#2059)", () => {
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

  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockImplementation(routes());
    auth.current = { user: { roles: ["admin"] } };
  });

  afterEach(() => {
    cleanup();
  });

  it("a non-admin sees the destructive controls disabled and the admin note", async () => {
    auth.current = { user: { roles: ["user"] } };
    renderPage();
    await screen.findByText("tenant-blue");
    await screen.findByText("aa:bb:cc:dd:ee:ff");
    for (const name of destructive) {
      expect((screen.getByRole("button", { name }) as HTMLButtonElement).disabled).toBe(true);
    }
    expect(screen.getByTestId("overlay-admin-note").textContent).toContain("Requires the admin role");
  });

  it("a non-admin click sends no DELETE", async () => {
    auth.current = { user: { roles: ["user"] } };
    renderPage();
    await screen.findByText("tenant-blue");
    await screen.findByText("aa:bb:cc:dd:ee:ff");
    fireEvent.change(screen.getByLabelText("MAC address"), { target: { value: "aa:bb:cc:dd:ee:ff" } });
    fireEvent.change(screen.getByLabelText("VNI"), { target: { value: "5001" } });
    for (const name of destructive) {
      fireEvent.click(screen.getByRole("button", { name }));
    }
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(callsTo("DELETE", `${base}/vnis/5001`)).toHaveLength(0);
    expect(callsTo("DELETE", `${base}/macs`)).toHaveLength(0);
  });

  it("without a session the controls are disabled", async () => {
    auth.current = null;
    renderPage();
    await screen.findByText("tenant-blue");
    await screen.findByText("aa:bb:cc:dd:ee:ff");
    for (const name of destructive) {
      expect((screen.getByRole("button", { name }) as HTMLButtonElement).disabled).toBe(true);
    }
    expect(screen.getByTestId("overlay-admin-note").textContent).toContain("Requires the admin role");
  });

  it("an admin gets the controls and no note", async () => {
    auth.current = { user: { roles: ["admin"] } };
    renderPage();
    await screen.findByText("tenant-blue");
    await screen.findByText("aa:bb:cc:dd:ee:ff");
    // #2059: the capability gate opens once the capabilities read lands.
    await waitFor(() => {
      for (const name of destructive) {
        expect((screen.getByRole("button", { name }) as HTMLButtonElement).disabled).toBe(false);
      }
    });
    expect(screen.queryByTestId("overlay-admin-note")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Delete VNI 5001" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(callsTo("DELETE", `${base}/vnis/5001`)).toHaveLength(1));
  });
});
