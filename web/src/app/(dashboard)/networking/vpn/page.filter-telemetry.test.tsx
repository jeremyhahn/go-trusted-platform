import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import VPNPage from "./page";

// #2070 (Codex round 4 P1): the page shows gateway telemetry and sessions only
// from the status read of the gateway filter now applied. A refused filtered
// read, or one still loading, must not leave the previous gateways' telemetry
// and sessions on screen under the new filter.

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

const gatewayA = {
  gatewayId: "gateway-a",
  reportedAtUnix: "1760300000",
  reporting: true,
  running: true,
  admissions: "12",
  refusals: "1",
  lastRefusal: "posture violation",
  enrolledPeers: 3,
  leasesByDataPlane: { masque: 2, wireguard: 1 },
  leases: [
    {
      id: "lease-1",
      tenantId: "acme",
      deviceId: "laptop-1",
      address: "192.0.2.10",
      dataPlane: "masque",
      zones: ["management"],
      issuedAtUnix: "1760300000",
      expiresAtUnix: "1760328800",
      renewals: 4,
    },
  ],
  posturePolicyErrors: [],
  rejectedPeers: [],
  revocations: { expired: "2" },
  postureViolations: { "secure-boot": "1" },
  reattest: { count: "2", sumSeconds: 0.04, buckets: [{ upperBoundSeconds: 0.05, count: "2" }] },
};

const VPN_OPS = [
  "GET /api/v1/vpn/status",
  "GET /api/v1/vpn/peers",
  "POST /api/v1/vpn/peers",
  "DELETE /api/v1/vpn/peers/{device_id}",
  "GET /api/v1/vpn/posture-policies",
  "GET /api/v1/vpn/posture-policies/{name}",
  "PUT /api/v1/vpn/posture-policies/{name}",
  "DELETE /api/v1/vpn/posture-policies/{name}",
];

/**
 * Answers the status read by its `gateway_id` query: no filter reports
 * gateway-a, `unknown` is refused with 404, and `gateway-b` waits for the
 * test to resolve it by hand.
 */
function routes(pendingB?: Promise<Response>) {
  return (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    if (method === "GET" && url.pathname === "/api/v1/capabilities") {
      const capabilities = VPN_OPS.map((op) => ({ op, kind: "route", enabled: true }));
      return Promise.resolve(ok({ capabilities, total: capabilities.length, enabled: capabilities.length }));
    }
    if (method === "GET" && url.pathname === "/api/v1/vpn/status") {
      const gateway = url.searchParams.get("gateway_id");
      if (!gateway) {
        return Promise.resolve(ok({ gateways: [gatewayA] }));
      }
      if (gateway === "unknown") {
        return Promise.resolve(failure(404, "gateway unknown has not reported"));
      }
      if (gateway === "gateway-b" && pendingB) {
        return pendingB;
      }
      return Promise.resolve(ok({ gateways: [] }));
    }
    if (method === "GET" && url.pathname === "/api/v1/vpn/peers") {
      return Promise.resolve(ok({ peers: [peer] }));
    }
    if (method === "GET" && url.pathname === "/api/v1/vpn/posture-policies") {
      return Promise.resolve(ok({ policies: [] }));
    }
    return Promise.resolve(failure(404, `no route ${method} ${url.pathname}`));
  };
}

describe("VPNPage telemetry follows the gateway filter", () => {
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

  /** Renders the page and waits for gateway-a's telemetry and its session. */
  async function renderPopulated() {
    renderPage();
    await screen.findByTestId("vpn-gateway-detail-gateway-a");
    await within(screen.getByTestId("vpn-sessions-card")).findByText("192.0.2.10");
  }

  function applyGatewayFilter(value: string) {
    fireEvent.change(screen.getByRole("textbox", { name: "Gateway" }), { target: { value } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
  }

  beforeEach(() => {
    fetchMock.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("a refused gateway filter hides the previous gateways telemetry and sessions", async () => {
    fetchMock.mockImplementation(routes());
    await renderPopulated();

    applyGatewayFilter("unknown");
    await screen.findByTestId("vpn-status-error");

    expect(screen.queryByTestId("vpn-gateway-detail-gateway-a")).toBeNull();
    expect(screen.queryByText("192.0.2.10")).toBeNull();
    expect(within(screen.getByTestId("vpn-sessions-card")).getByText("No live sessions.")).toBeTruthy();
  });

  it("while a new gateway filter loads, the previous gateway sessions are not shown", async () => {
    let resolveB: (response: Response) => void = () => undefined;
    const pendingB = new Promise<Response>((resolve) => {
      resolveB = resolve;
    });
    fetchMock.mockImplementation(routes(pendingB));
    await renderPopulated();

    applyGatewayFilter("gateway-b");
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(([input]) => new URL(String(input)).searchParams.get("gateway_id") === "gateway-b")
      ).toBe(true)
    );

    expect(screen.queryByTestId("vpn-gateway-detail-gateway-a")).toBeNull();
    expect(screen.queryByText("192.0.2.10")).toBeNull();

    resolveB(ok({ gateways: [] }));
    await screen.findByText("No gateway has reported yet.");
    expect(screen.queryByTestId("vpn-gateway-detail-gateway-a")).toBeNull();
    expect(within(screen.getByTestId("vpn-sessions-card")).getByText("No live sessions.")).toBeTruthy();
  });

  it("clearing the filter after a refused read shows the gateways again", async () => {
    fetchMock.mockImplementation(routes());
    await renderPopulated();

    applyGatewayFilter("unknown");
    await screen.findByTestId("vpn-status-error");

    fireEvent.click(screen.getAllByRole("button", { name: "Clear filters" })[0]);
    await screen.findByTestId("vpn-gateway-detail-gateway-a");
    await within(screen.getByTestId("vpn-sessions-card")).findByText("192.0.2.10");
    expect(screen.queryByTestId("vpn-status-error")).toBeNull();
  });
});
