import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import VPNPage from "./page";

// #2070 (Codex round 5 P1): the page shows peers and posture policies, and
// their Revoke / Edit / Delete actions, only from the reads of the tenant
// filter now applied. While a new tenant's reads are pending, the previous
// tenant's rows must not stay on screen or stay actionable.

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

const peerA = { tenantId: "acme", deviceId: "laptop-1", zones: ["management"], enrolledAtUnix: "1760300000" };
const policyA = { tenantId: "acme", name: "corp", module: "package vpn.posture\n", updatedAtUnix: "1760300000" };
const peerB = { tenantId: "globex", deviceId: "phone-2", zones: ["management"], enrolledAtUnix: "1760300000" };
const policyB = { tenantId: "globex", name: "strict", module: "package vpn.posture\n", updatedAtUnix: "1760300000" };

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

interface Deferred {
  promise: Promise<Response>;
  resolve: (response: Response) => void;
}

function deferred(): Deferred {
  let resolve: (response: Response) => void = () => undefined;
  const promise = new Promise<Response>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/**
 * No tenant filter answers tenant A's peers and policies; `tenant_id=globex`
 * waits for the test to resolve the two reads by hand.
 */
function routes(peersB: Deferred, policiesB: Deferred) {
  return (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    const tenant = url.searchParams.get("tenant_id");
    if (method === "GET" && url.pathname === "/api/v1/capabilities") {
      const capabilities = VPN_OPS.map((op) => ({ op, kind: "route", enabled: true }));
      return Promise.resolve(ok({ capabilities, total: capabilities.length, enabled: capabilities.length }));
    }
    if (method === "GET" && url.pathname === "/api/v1/vpn/status") {
      return Promise.resolve(ok({ gateways: [] }));
    }
    if (method === "GET" && url.pathname === "/api/v1/vpn/peers") {
      if (tenant === "globex") {
        return peersB.promise;
      }
      return Promise.resolve(ok({ peers: tenant ? [] : [peerA] }));
    }
    if (method === "GET" && url.pathname === "/api/v1/vpn/posture-policies") {
      if (tenant === "globex") {
        return policiesB.promise;
      }
      return Promise.resolve(ok({ policies: tenant ? [] : [policyA] }));
    }
    return Promise.resolve(failure(404, `no route ${method} ${url.pathname}`));
  };
}

describe("VPNPage peers and policies follow the tenant filter", () => {
  const fetchMock = vi.fn<typeof fetch>();
  let peersB: Deferred;
  let policiesB: Deferred;

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

  function calledFor(path: string, tenant: string): boolean {
    return fetchMock.mock.calls.some(([input]) => {
      const url = new URL(String(input));
      return url.pathname === path && url.searchParams.get("tenant_id") === tenant;
    });
  }

  /** Renders tenant A, applies tenant B and waits until both B reads are sent. */
  async function renderThenApplyGlobex() {
    renderPage();
    await screen.findByRole("button", { name: "Revoke laptop-1" });
    await screen.findByRole("button", { name: "Edit corp" });

    fireEvent.change(screen.getByRole("textbox", { name: "Tenant" }), { target: { value: "globex" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => {
      expect(calledFor("/api/v1/vpn/peers", "globex")).toBe(true);
      expect(calledFor("/api/v1/vpn/posture-policies", "globex")).toBe(true);
    });
  }

  async function answerGlobex() {
    peersB.resolve(ok({ peers: [peerB] }));
    policiesB.resolve(ok({ policies: [policyB] }));
    await screen.findByRole("button", { name: "Revoke phone-2" });
    await screen.findByRole("button", { name: "Edit strict" });
  }

  beforeEach(() => {
    fetchMock.mockReset();
    peersB = deferred();
    policiesB = deferred();
    fetchMock.mockImplementation(routes(peersB, policiesB));
  });

  afterEach(() => {
    cleanup();
  });

  it("while tenant B loads, tenant A peers, policies and their actions are gone", async () => {
    await renderThenApplyGlobex();

    expect(screen.queryByText("laptop-1")).toBeNull();
    expect(screen.queryByText("corp")).toBeNull();
    expect(screen.queryByRole("button", { name: "Revoke laptop-1" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit corp" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete corp" })).toBeNull();
  });

  it("after tenant B answers, only its rows and actions show", async () => {
    await renderThenApplyGlobex();
    await answerGlobex();

    expect(screen.queryByText("laptop-1")).toBeNull();
    expect(screen.queryByRole("button", { name: "Revoke laptop-1" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit corp" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete corp" })).toBeNull();
  });

  it("clearing the tenant filter brings tenant A back", async () => {
    await renderThenApplyGlobex();
    await answerGlobex();

    fireEvent.click(screen.getAllByRole("button", { name: "Clear filters" })[0]);
    await screen.findByRole("button", { name: "Revoke laptop-1" });
    await screen.findByRole("button", { name: "Edit corp" });
    expect(screen.queryByText("phone-2")).toBeNull();
    expect(screen.queryByRole("button", { name: "Revoke phone-2" })).toBeNull();
  });
});
