import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import VPNPage from "./page";

// #2070: the real-server Playwright spec (web/e2e/real-server/vpn.spec.ts)
// finds the VPN page's cards by data-testid. These tests pin those handles
// against the same fetch stub page.test.tsx uses.

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
  gatewayId: "gateway-a",
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

describe("VPNPage test ids", () => {
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

  beforeEach(() => {
    fetchMock.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("the loaded page marks the gateways, sessions, peers and policies cards", async () => {
    fetchMock.mockImplementation(routes());

    renderPage();

    expect(await screen.findByTestId("vpn-peers-card")).toBeTruthy();
    expect(await within(screen.getByTestId("vpn-peers-card")).findByText("laptop-1")).toBeTruthy();
    expect(await within(screen.getByTestId("vpn-policies-card")).findByText("corp")).toBeTruthy();
    expect(await within(screen.getByTestId("vpn-sessions-card")).findByText("10.8.0.2")).toBeTruthy();
    expect(screen.getByTestId("vpn-gateways-card")).toBeTruthy();
  });

  it("a node without a VPN control plane marks the unavailable state", async () => {
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

    expect(await screen.findByTestId("vpn-unavailable")).toBeTruthy();
    expect(screen.queryByTestId("vpn-peers-card")).toBeNull();
  });

  it("a refused GetStatus marks the status error, not the gateways table", async () => {
    fetchMock.mockImplementation(
      routes((method, url) =>
        method === "GET" && url.pathname === "/api/v1/vpn/status" ? failure(500, "status down") : undefined
      )
    );

    renderPage();

    expect((await screen.findByTestId("vpn-status-error")).textContent).toContain("status down");
    expect(screen.queryByTestId("vpn-gateways-table")).toBeNull();
  });

  it("a successful GetStatus renders the gateways table", async () => {
    fetchMock.mockImplementation(routes());

    renderPage();

    expect(within(await screen.findByTestId("vpn-gateways-table")).getByText("gateway-a")).toBeTruthy();
    expect(screen.queryByTestId("vpn-status-error")).toBeNull();
  });
});
