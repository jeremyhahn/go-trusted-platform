import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import ZonesPage from "./page";

// #2065: the page drives the network zones through client.sdn on the REST
// zone shape (pkg/webservice/v1/rest/sdn/zones.go). These tests stub the
// client's fetch with the {code,error,success,payload} envelopes the
// webservice writes; the global fetch refuses, so a hand-written call fails.

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

describe("ZonesPage", () => {
  const fetchMock = vi.fn<typeof fetch>();
  const globalFetch = vi.fn(() => Promise.reject(new Error("global fetch")));

  function renderPage() {
    const client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: fetchMock,
      retry: { maxRetries: 0 },
    });
    return render(
      <PlatformProvider client={client}>
        <ZonesPage />
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
    globalFetch.mockClear();
    vi.stubGlobal("fetch", globalFetch);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    cleanup();
  });

  it("lists the zones through client.sdn", async () => {
    fetchMock.mockImplementation((input, init) => {
      const url = new URL(String(input));
      if ((init?.method ?? "GET") === "GET" && url.pathname === "/api/v1/sdn/zones") {
        return Promise.resolve(
          ok({
            zones: [
              {
                name: "management",
                offset: 2,
                isolate: true,
                created_at: "2026-11-01T00:00:00Z",
                updated_at: "2026-11-01T00:00:00Z",
              },
              {
                name: "lab",
                offset: 9,
                port_classes: ["hypervisor"],
                created_at: "2026-11-01T00:00:00Z",
                updated_at: "2026-11-01T00:00:00Z",
              },
            ],
            count: 2,
            timestamp: "2026-11-01T00:00:00Z",
          })
        );
      }
      return Promise.resolve(failure(404, `no route ${url.pathname}`));
    });

    renderPage();

    expect(await screen.findByText("lab")).toBeTruthy();
    expect(screen.getByText("management")).toBeTruthy();
    expect(callsTo("GET", "/api/v1/sdn/zones")).toHaveLength(1);
    expect(globalFetch).not.toHaveBeenCalled();
  });

  it("shows the server error when the list fails", async () => {
    fetchMock.mockImplementation(() => Promise.resolve(failure(500, "list zones: boom")));

    renderPage();

    expect(await screen.findByText("Error Loading Zones")).toBeTruthy();
    expect(screen.getByText(/list zones: boom/)).toBeTruthy();
    expect(globalFetch).not.toHaveBeenCalled();
  });
});
