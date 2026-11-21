import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import NTPPage from "./page";

// #2058: the NTP page reads and steps the clock through the SDK's NTPService
// and gates Step Clock on the server's capabilities. These tests stub fetch,
// the boundary the browser crosses, with the envelopes the webservice writes.

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
  synced: true,
  stratum: 2,
  leapStatus: "normal",
  offsetSeconds: 0.0001,
  rootDispersion: 0.001,
  rootDelay: 0.002,
  lastSyncUnix: "1760300000",
  mode: "client",
  referenceId: "C0A80001",
  referenceName: "ntp.reference.test",
  sourcesReachable: 1,
  sourcesTotal: 1,
  anomaly: false,
  anomalyReason: "",
};

const source = {
  address: "10.0.0.1",
  mode: "server",
  state: "selected",
  stratum: 1,
  pollSeconds: 64,
  reach: 255,
  lastRxSeconds: "12",
  offsetSeconds: 0.0001,
  reachable: true,
};

type Capability = { op: string; kind: string; enabled: boolean; reason?: string };

const statusCap: Capability = { op: "GET /api/v1/ntp/status", kind: "route", enabled: true };
const sourcesCap: Capability = { op: "GET /api/v1/ntp/sources", kind: "route", enabled: true };
const stepCap: Capability = { op: "POST /api/v1/ntp/step", kind: "route", enabled: true };

/** Answers the capabilities read with `caps` and the two NTP reads with one status and one source. */
function routes(caps: Capability[]) {
  return (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    if (method === "GET" && url.pathname === "/api/v1/capabilities") {
      return Promise.resolve(
        ok({ capabilities: caps, total: caps.length, enabled: caps.filter((c) => c.enabled).length })
      );
    }
    if (method === "GET" && url.pathname === "/api/v1/ntp/status") {
      return Promise.resolve(ok({ status }));
    }
    if (method === "GET" && url.pathname === "/api/v1/ntp/sources") {
      return Promise.resolve(ok({ sources: [source] }));
    }
    return Promise.resolve(failure(404, `no route ${method} ${url.pathname}`));
  };
}

describe("NTPPage", () => {
  const fetchMock = vi.fn<typeof fetch>();

  function renderPage() {
    const client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: fetchMock,
      retry: { maxRetries: 0 },
    });
    return render(
      <PlatformProvider client={client}>
        <NTPPage />
      </PlatformProvider>
    );
  }

  /** The calls fetch saw under one path prefix. */
  function callsUnder(prefix: string) {
    return fetchMock.mock.calls.filter(([input]) => new URL(String(input)).pathname.startsWith(prefix));
  }

  function stepButton() {
    return screen.getByRole("button", { name: "Step Clock" }) as HTMLButtonElement;
  }

  beforeEach(() => {
    fetchMock.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("with step enabled the Step Clock button is enabled and the status card shows the reference", async () => {
    fetchMock.mockImplementation(routes([statusCap, sourcesCap, stepCap]));

    renderPage();

    expect(await screen.findByText("ntp.reference.test")).toBeTruthy();
    await waitFor(() => expect(stepButton().getAttribute("data-capability-enabled")).toBe("true"));
    expect(stepButton().disabled).toBe(false);
    expect(stepButton().getAttribute("data-capability-op")).toBe("POST /api/v1/ntp/step");
  });

  it("with step disabled the button is disabled with the reason as its title", async () => {
    fetchMock.mockImplementation(
      routes([statusCap, sourcesCap, { ...stepCap, enabled: false, reason: "unimplemented" }])
    );

    renderPage();

    expect(await screen.findByText("ntp.reference.test")).toBeTruthy();
    await waitFor(() => expect(stepButton().title).toBe("unimplemented"));
    expect(stepButton().disabled).toBe(true);
  });

  it("with ntp status not offered the page shows ntp-not-enabled and makes no /v1/ntp call", async () => {
    fetchMock.mockImplementation(routes([stepCap]));

    renderPage();

    const card = await screen.findByTestId("ntp-not-enabled");
    expect(card.textContent).toContain("NTP is not enabled on this server");
    expect(card.textContent).toContain("not offered by this server");
    expect(callsUnder("/api/v1/ntp")).toHaveLength(0);
  });
});
