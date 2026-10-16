import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import VPNPage from "./page";

// #584: the page drives the VPN control plane through the SDK's REST routes
// (docs/vpn/api.md §1). These tests stub fetch, the boundary the browser
// crosses, with the protojson envelopes the webservice writes.

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

const peer = { tenantId: "acme", deviceId: "laptop-1", zones: ["management"], enrolledAtUnix: "1760300000" };

const policy = {
  tenantId: "acme",
  name: "corp",
  module: "package vpn.posture\n\ndeny contains \"secure_boot\" if not input.secure_boot.enabled\n",
  updatedAtUnix: "1760300000",
};

const gateway = {
  gatewayId: "gw-01",
  reportedAtUnix: "1760300000",
  reporting: true,
  running: true,
  admissions: "12",
  refusals: "1",
  lastRefusal: "posture violation",
  enrolledPeers: 1,
  leasesByDataPlane: { masque: 1 },
  leases: [
    {
      id: "lease-1",
      tenantId: "acme",
      deviceId: "laptop-1",
      address: "10.8.0.2",
      dataPlane: "masque",
      zones: ["management"],
      issuedAtUnix: "1760300000",
      expiresAtUnix: "1760328800",
      renewals: 0,
    },
  ],
  posturePolicyErrors: [],
  rejectedPeers: [{ tenantId: "acme", deviceId: "laptop-9", reason: "zone \"storage\" is not served" }],
  revocations: { expired: "2" },
  postureViolations: { "secure-boot": "1" },
  reattest: { count: "1", sumSeconds: 0.04, buckets: [{ upperBoundSeconds: 0.05, count: "1" }] },
};

type Route = (method: string, url: URL, body: unknown) => Response | undefined;

/** Answers the three list reads with one peer, one policy and one gateway, then defers to `extra`. */
function routes(extra: Route = () => undefined) {
  return (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    const answer = extra(method, url, body);
    if (answer) {
      return Promise.resolve(answer);
    }
    if (method === "GET" && url.pathname === "/api/v1/vpn/status") {
      return Promise.resolve(ok({ gateways: [gateway] }));
    }
    if (method === "GET" && url.pathname === "/api/v1/vpn/peers") {
      return Promise.resolve(ok({ peers: [peer] }));
    }
    if (method === "GET" && url.pathname === "/api/v1/vpn/posture-policies") {
      return Promise.resolve(ok({ policies: [policy] }));
    }
    return Promise.resolve(failure(404, `no route ${method} ${url.pathname}`));
  };
}

describe("VPNPage", () => {
  const fetchMock = vi.fn<typeof fetch>();

  function renderPage() {
    const client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: fetchMock,
      retry: { maxRetries: 0 },
    });
    return render(
      <PlatformProvider client={client}>
        <VPNPage />
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
  });

  afterEach(() => {
    cleanup();
  });

  it("lists the gateways' sessions, the enrolled peers and the posture policies", async () => {
    fetchMock.mockImplementation(routes());

    renderPage();

    expect(await screen.findByText("10.8.0.2")).toBeTruthy();
    expect(screen.getByText("gw-01 refused acme/laptop-9")).toBeTruthy();
    expect(screen.getByText("posture violation")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Revoke laptop-1" })).toBeTruthy();
    expect(screen.getByText("corp")).toBeTruthy();
  });

  it("shows the unavailable state on a node without a VPN control plane", async () => {
    const notConfigured = () =>
      jsonResponse(503, {
        code: 503,
        error: "vpn service not configured",
        success: false,
        service: "vpn",
        reason: "SERVICE_NOT_CONFIGURED",
      });
    fetchMock.mockImplementation(() => Promise.resolve(notConfigured()));

    renderPage();

    expect(await screen.findByText("VPN is not available on this node")).toBeTruthy();
    expect(screen.queryByText("Enrolled Peers")).toBeNull();
  });

  it("still lists peers and policies when gateway status is unavailable", async () => {
    fetchMock.mockImplementation(
      routes((method, url) =>
        method === "GET" && url.pathname === "/api/v1/vpn/status"
          ? failure(503, "vpn: gateway status is unavailable")
          : undefined
      )
    );

    renderPage();

    expect(
      await screen.findByText("Session status is unavailable: vpn: gateway status is unavailable")
    ).toBeTruthy();
    expect(screen.getByRole("button", { name: "Revoke laptop-1" })).toBeTruthy();
  });

  it("revokes a peer under its tenant after confirmation", async () => {
    fetchMock.mockImplementation(
      routes((method, url) =>
        method === "DELETE" && url.pathname === "/api/v1/vpn/peers/laptop-1" ? ok({}) : undefined
      )
    );

    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Revoke laptop-1" }));
    fireEvent.click(await screen.findByRole("button", { name: "Confirm Revoke" }));

    await waitFor(() => expect(screen.queryByRole("button", { name: "Confirm Revoke" })).toBeNull());
    const [call] = callsTo("DELETE", "/api/v1/vpn/peers/laptop-1");
    expect(new URL(String(call?.[0])).searchParams.get("tenant_id")).toBe("acme");
  });

  it("keeps the revoke dialog open when the revoke is refused", async () => {
    fetchMock.mockImplementation(
      routes((method) => (method === "DELETE" ? failure(404, "vpn: peer not found") : undefined))
    );

    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Revoke laptop-1" }));
    fireEvent.click(await screen.findByRole("button", { name: "Confirm Revoke" }));

    await waitFor(() => expect(callsTo("DELETE", "/api/v1/vpn/peers/laptop-1")).toHaveLength(1));
    await waitFor(() =>
      expect(
        (screen.getByRole("button", { name: "Confirm Revoke" }) as HTMLButtonElement).disabled
      ).toBe(false)
    );
  });

  it("opens a stored policy and saves the edited module", async () => {
    const edited = "package vpn.posture\n\ndeny contains \"fde\" if not input.fde.root_encrypted\n";
    fetchMock.mockImplementation(
      routes((method, url, body) => {
        if (url.pathname !== "/api/v1/vpn/posture-policies/corp") {
          return undefined;
        }
        if (method === "GET") {
          return ok({ policy });
        }
        if (method === "PUT") {
          return ok({ policy: { ...(body as object), updatedAtUnix: "1760300100" } });
        }
        return undefined;
      })
    );

    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Edit corp" }));
    const module = (await screen.findByLabelText("Module *")) as HTMLTextAreaElement;
    expect(module.value).toBe(policy.module);
    fireEvent.change(module, { target: { value: edited } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(screen.queryByLabelText("Module *")).toBeNull());
    const [call] = callsTo("PUT", "/api/v1/vpn/posture-policies/corp");
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ tenantId: "acme", name: "corp", module: edited });
  });

  it("keeps the editor open when the module is refused", async () => {
    fetchMock.mockImplementation(
      routes((method, url) => {
        if (url.pathname !== "/api/v1/vpn/posture-policies/corp") {
          return undefined;
        }
        if (method === "GET") {
          return ok({ policy });
        }
        if (method === "PUT") {
          return failure(400, "vpn: invalid posture policy: rego_parse_error");
        }
        return undefined;
      })
    );

    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Edit corp" }));
    const module = await screen.findByLabelText("Module *");
    fireEvent.change(module, { target: { value: "package wrong" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(callsTo("PUT", "/api/v1/vpn/posture-policies/corp")).toHaveLength(1));
    await waitFor(() =>
      expect((screen.getByRole("button", { name: "Save" }) as HTMLButtonElement).disabled).toBe(false)
    );
    expect((screen.getByLabelText("Module *") as HTMLTextAreaElement).value).toBe("package wrong");
  });

  it("creates a new policy with the tenant and name the operator enters", async () => {
    fetchMock.mockImplementation(
      routes((method, url, body) =>
        method === "PUT" && url.pathname === "/api/v1/vpn/posture-policies/strict"
          ? ok({ policy: { ...(body as object), updatedAtUnix: "1760300100" } })
          : undefined
      )
    );

    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "New Policy" }));
    fireEvent.change(await screen.findByLabelText("Tenant *"), { target: { value: "acme" } });
    fireEvent.change(screen.getByLabelText("Name *"), { target: { value: "strict" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(callsTo("PUT", "/api/v1/vpn/posture-policies/strict")).toHaveLength(1));
    const [call] = callsTo("PUT", "/api/v1/vpn/posture-policies/strict");
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({
      tenantId: "acme",
      name: "strict",
      module: "package vpn.posture\n",
    });
  });
});
