import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import OverlayVtepsPage from "./page";
const auth: { current: { user: { roles: string[] } } | null } = { current: { user: { roles: ["admin"] } } };
vi.mock("@/contexts/AuthContext", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/contexts/AuthContext")>()), useOptionalAuth: () => auth.current }));

// #2059: on top of the admin-role check, Delete VNI and both Forget MAC
// controls sit in the capability gate on their server route ops, so an op
// the server does not offer disables the control with the server's reason.

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

const DELETE_VNI_OP = "DELETE /api/v1/overlay/vnis/{vni:[0-9]+}";
const DELETE_MACS_OP = "DELETE /api/v1/overlay/macs";

const OVERLAY_OPS = [
  "GET /api/v1/overlay/status",
  "GET /api/v1/overlay/vteps",
  "GET /api/v1/overlay/vteps/{nodeId}",
  "GET /api/v1/overlay/vnis",
  "GET /api/v1/overlay/tunnels",
  "GET /api/v1/overlay/tunnels/stats",
  "GET /api/v1/overlay/macs",
  DELETE_VNI_OP,
  DELETE_MACS_OP,
];

/** The capabilities answer with the ops in `off` disabled. */
function caps(off: string[] = []): Response {
  const capabilities = OVERLAY_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: "route", enabled: false, reason: "not-configured: overlay" }
      : { op, kind: "route", enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

/** Answers every overlay read, the two deletes and the capabilities read. */
function routes(off: string[] = []) {
  return (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const key = `${method} ${url.pathname}`;
    switch (key) {
      case `GET /api/v1/capabilities`:
        return Promise.resolve(caps(off));
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

const DELETE_VNI = "Delete VNI 5001";
const FORGET_ROW = "Forget aa:bb:cc:dd:ee:ff on VNI 5001";
const FORGET_FORM = "Forget MAC";

describe("OverlayVtepsPage capability gate (#2059)", () => {
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

  function button(name: string) {
    return screen.getByRole("button", { name }) as HTMLButtonElement;
  }

  /** Renders the page and waits until the capabilities answer has landed. */
  async function renderLoaded(off: string[] = []) {
    fetchMock.mockImplementation(routes(off));
    renderPage();
    await screen.findByText("tenant-blue");
    await screen.findByText("aa:bb:cc:dd:ee:ff");
    await waitFor(() => expect(callsTo("GET", "/api/v1/capabilities").length).toBeGreaterThan(0));
    await waitFor(() => {
      for (const name of [DELETE_VNI, FORGET_ROW, FORGET_FORM]) {
        expect(button(name).getAttribute("data-capability-op")).not.toBeNull();
        expect(button(name).title).not.toBe("checking server capabilities");
      }
    });
  }

  beforeEach(() => {
    fetchMock.mockReset();
    auth.current = { user: { roles: ["admin"] } };
  });

  afterEach(() => {
    cleanup();
  });

  it("marks each destructive control with its route op", async () => {
    await renderLoaded();
    const expected: Array<[string, string]> = [
      [DELETE_VNI, DELETE_VNI_OP],
      [FORGET_ROW, DELETE_MACS_OP],
      [FORGET_FORM, DELETE_MACS_OP],
    ];
    for (const [name, op] of expected) {
      const b = button(name);
      expect(b.getAttribute("data-capability-op")).toBe(op);
      expect(b.getAttribute("data-capability-enabled")).toBe("true");
      expect(b.disabled).toBe(false);
    }
  });

  it("disables Delete VNI with the reason when the server does not offer it", async () => {
    await renderLoaded([DELETE_VNI_OP]);
    const del = button(DELETE_VNI);
    expect(del.disabled).toBe(true);
    expect(del.title).toBe("not-configured: overlay");
    expect(del.getAttribute("data-capability-enabled")).toBe("false");
    expect(button(FORGET_ROW).disabled).toBe(false);
    expect(button(FORGET_FORM).disabled).toBe(false);

    fireEvent.click(del);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(callsTo("DELETE", `${base}/vnis/5001`)).toHaveLength(0);
  });

  it("disables both Forget controls when the server does not offer DELETE /macs", async () => {
    await renderLoaded([DELETE_MACS_OP]);
    for (const name of [FORGET_ROW, FORGET_FORM]) {
      const b = button(name);
      expect(b.disabled).toBe(true);
      expect(b.title).toBe("not-configured: overlay");
      expect(b.getAttribute("data-capability-enabled")).toBe("false");
    }
    expect(button(DELETE_VNI).disabled).toBe(false);

    fireEvent.change(screen.getByLabelText("MAC address"), { target: { value: "02:00:00:00:00:01" } });
    fireEvent.change(screen.getByLabelText("VNI"), { target: { value: "5001" } });
    fireEvent.click(button(FORGET_ROW));
    fireEvent.click(button(FORGET_FORM));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(callsTo("DELETE", `${base}/macs`)).toHaveLength(0);
  });

  it("keeps the admin check: a non-admin stays disabled even with the op on", async () => {
    auth.current = { user: { roles: ["user"] } };
    await renderLoaded();
    for (const name of [DELETE_VNI, FORGET_ROW, FORGET_FORM]) {
      const b = button(name);
      expect(b.getAttribute("data-capability-enabled")).toBe("true");
      expect(b.disabled).toBe(true);
    }
  });
});
