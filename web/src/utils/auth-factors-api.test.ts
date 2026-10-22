import { ErrorCode } from "trusted-platform-sdk";
import { afterEach, describe, expect, it, vi } from "vitest";

import { authFactorsApi, toApiResponse } from "./auth-factors-api";

const CSR_PEM = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("authFactorsApi.issueMTLSCert", () => {
  it("posts the CSR as csr_pem to the user's issue-cert route", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(201, { cert_pem: "CERT", chain_pem: "CHAIN" }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await authFactorsApi.issueMTLSCert("alice@example", CSR_PEM);

    expect(result).toEqual({ ok: true, data: { cert_pem: "CERT", chain_pem: "CHAIN" } });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/users\/alice%40example\/factors\/mtls\/issue-cert$/);
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ csr_pem: CSR_PEM });
  });

  it("returns the handler's error when it refuses the CSR", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(403, { error: "CSR is not bound to the user: CN=mallory" }))
    );

    const result = await authFactorsApi.issueMTLSCert("alice", CSR_PEM);

    expect(result).toEqual({ ok: false, error: "CSR is not bound to the user: CN=mallory", status: 403 });
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
