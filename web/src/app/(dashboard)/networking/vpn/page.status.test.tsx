import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import VPNPage from "./page";

// #2070: the page shows the whole GetStatus answer (docs/vpn/api.md §1):
// each gateway's enrolled peers, leases by data plane, revocations, posture
// violations and re-attestation time, and each session's issue time and
// renewals. These tests stub fetch with the protojson envelopes the
// webservice writes.

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

const gatewayQuiet = {
  ...gatewayA,
  gatewayId: "gateway-q",
  enrolledPeers: 0,
  leasesByDataPlane: {},
  leases: [],
  revocations: {},
  postureViolations: {},
  reattest: null,
};

const gatewayB = {
  ...gatewayQuiet,
  gatewayId: "gateway-b",
  reporting: false,
  running: false,
};

type Route = (method: string, url: URL, body: unknown) => Response | undefined;

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

/** Answers the list reads with `gateways`, one peer and no policy, then defers to `extra`. */
function routes(gateways: unknown[] = [gatewayA], extra: Route = () => undefined) {
  return (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    const answer = extra(method, url, body);
    if (answer) {
      return Promise.resolve(answer);
    }
    if (method === "GET" && url.pathname === "/api/v1/capabilities") {
      const capabilities = VPN_OPS.map((op) => ({ op, kind: "route", enabled: true }));
      return Promise.resolve(ok({ capabilities, total: capabilities.length, enabled: capabilities.length }));
    }
    if (method === "GET" && url.pathname === "/api/v1/vpn/status") {
      return Promise.resolve(ok({ gateways }));
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

describe("VPNPage status", () => {
  const fetchMock = vi.fn<typeof fetch>();

  /** A page control once the capability gate has opened it. */
  async function enabledButton(name: string) {
    const b = await screen.findByRole("button", { name });
    await waitFor(() => expect(b.getAttribute("data-capability-enabled")).toBe("true"));
    return b;
  }

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

  it("the gateways table shows each gateway's enrolled peers", async () => {
    fetchMock.mockImplementation(routes());
    renderPage();

    const table = await screen.findByTestId("vpn-gateways-table");
    expect(within(table).getByRole("columnheader", { name: "Peers" })).toBeTruthy();
    const row = within(table).getByText("gateway-a").closest("tr");
    expect(row).not.toBeNull();
    expect(within(row as HTMLElement).getByRole("cell", { name: "3" })).toBeTruthy();
  });

  it("a reporting gateway shows its leases by data plane, revocations, posture violations and re-attestation time", async () => {
    fetchMock.mockImplementation(routes());
    renderPage();

    const detail = await screen.findByTestId("vpn-gateway-detail-gateway-a");
    expect(within(detail).getByText(/masque: 2/)).toBeTruthy();
    expect(within(detail).getByText(/wireguard: 1/)).toBeTruthy();
    expect(within(detail).getByText(/expired: 2/)).toBeTruthy();
    expect(within(detail).getByText(/secure-boot: 1/)).toBeTruthy();
    expect(within(detail).getByText(/2 re-attestations, mean 20 ms/)).toBeTruthy();
  });

  it("empty telemetry reads none", async () => {
    fetchMock.mockImplementation(routes([gatewayQuiet]));
    renderPage();

    const detail = await screen.findByTestId("vpn-gateway-detail-gateway-q");
    expect(within(detail).getAllByText("none")).toHaveLength(3);
    expect(within(detail).getByText("no re-attestations")).toBeTruthy();
  });

  it("a gateway that reports no VPN section has no detail block", async () => {
    fetchMock.mockImplementation(routes([gatewayA, gatewayB]));
    renderPage();

    await screen.findByTestId("vpn-gateway-detail-gateway-a");
    expect(within(screen.getByTestId("vpn-gateways-table")).getByText("gateway-b")).toBeTruthy();
    expect(screen.queryByTestId("vpn-gateway-detail-gateway-b")).toBeNull();
  });

  it("each session shows when it was issued and how often it renewed", async () => {
    fetchMock.mockImplementation(routes());
    renderPage();

    const card = await screen.findByTestId("vpn-sessions-card");
    await within(card).findByText("192.0.2.10");
    expect(within(card).getByRole("columnheader", { name: "Issued" })).toBeTruthy();
    expect(within(card).getByRole("columnheader", { name: "Renewals" })).toBeTruthy();
    expect(within(card).getByRole("cell", { name: "4" })).toBeTruthy();
  });

  it("enrolling a peer re-reads the status", async () => {
    fetchMock.mockImplementation(
      routes([gatewayA], (method, url, body) =>
        method === "POST" && url.pathname === "/api/v1/vpn/peers"
          ? ok({ peer: { ...(body as object), enrolledAtUnix: "1760300100" } })
          : undefined
      )
    );
    renderPage();

    await screen.findByTestId("vpn-gateway-detail-gateway-a");
    fireEvent.click(await enabledButton("Enrol Peer"));
    fireEvent.change(await screen.findByLabelText("Tenant *"), { target: { value: "acme" } });
    fireEvent.change(screen.getByLabelText("Device ID *"), { target: { value: "laptop-2" } });
    const before = callsTo("GET", "/api/v1/vpn/status").length;
    fireEvent.click(screen.getByRole("button", { name: "Enrol" }));

    await waitFor(() => expect(callsTo("POST", "/api/v1/vpn/peers")).toHaveLength(1));
    await waitFor(() => expect(callsTo("GET", "/api/v1/vpn/status")).toHaveLength(before + 1));
  });
});
