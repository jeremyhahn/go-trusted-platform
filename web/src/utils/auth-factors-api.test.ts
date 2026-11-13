import { ErrorCode } from "trusted-platform-sdk";
import { afterEach, describe, expect, it, vi } from "vitest";

import { probeMTLS, toApiResponse } from "./auth-factors-api";

describe("probeMTLS", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function answer(status: number) {
    const fetchMock = vi.fn(() => Promise.resolve(new Response(null, { status })));
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("asks the webservice's probe route with a HEAD", async () => {
    const fetchMock = answer(204);

    expect(await probeMTLS()).toEqual({ status: "available" });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/auth\/mtls\/probe$/);
    expect(init.method).toBe("HEAD");
  });

  it("reads 501 as a deployment that cannot sign in with a certificate (#201)", async () => {
    answer(501);

    expect(await probeMTLS()).toEqual({ status: "not-supported" });
  });

  it("reads 404 from a server without the route as not supported", async () => {
    answer(404);

    expect(await probeMTLS()).toEqual({ status: "not-supported" });
  });

  it("reads 401 as no client certificate", async () => {
    answer(401);

    expect(await probeMTLS()).toEqual({ status: "no-client-certificate" });
  });
});

describe("toApiResponse", () => {
  it("carries the data of a successful result", () => {
    const data = { factors: [], total: 0 };

    expect(toApiResponse({ ok: true, data })).toEqual({ success: true, data });
  });

  it("maps an HTTP failure to the SDK code for its status", () => {
    const response = toApiResponse({ ok: false, error: "no such user", status: 404 });

    expect(response).toEqual({
      success: false,
      error: { code: ErrorCode.NOT_FOUND, message: "no such user", status: 404 },
    });
  });

  it("maps a transport failure to NETWORK_ERROR without a status", () => {
    const response = toApiResponse({ ok: false, error: "Failed to fetch", status: 0 });

    expect(response).toEqual({
      success: false,
      error: { code: ErrorCode.NETWORK_ERROR, message: "Failed to fetch" },
    });
  });
});
