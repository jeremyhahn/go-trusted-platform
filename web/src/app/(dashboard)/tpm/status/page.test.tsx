import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import TPMStatusPage from "./page";

// #325: the page reads GET /api/v1/tpm/info, whose payload is the flat proto
// TPMInfoResponse with `version` spelled as the enum name. These tests drive
// the page through a stubbed fetch, the same boundary the browser crosses.

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const tpmInfo = {
  version: "TPM_VERSION_2_0",
  manufacturer: null,
  capabilities: [],
  pcrBanks: ["PCR_BANK_SHA256"],
  maxNvramSize: 2048,
  isSimulator: false,
  fipsMode: false,
  properties: {},
  nvIndexes: [],
};

/** Answers /tpm/info with the given response and every key probe with 404. */
function routeInfo(info: Response) {
  return (input: RequestInfo | URL) => {
    if (String(input).endsWith("/api/v1/tpm/info")) {
      return Promise.resolve(info);
    }
    return Promise.resolve(jsonResponse(404, { code: 404, error: "not found", success: false }));
  };
}

describe("TPMStatusPage TPM info", () => {
  const fetchMock = vi.fn<typeof fetch>();

  function renderPage() {
    const client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: fetchMock,
      retry: { maxRetries: 0 },
    });
    return render(
      <PlatformProvider client={client}>
        <TPMStatusPage />
      </PlatformProvider>
    );
  }

  beforeEach(() => {
    fetchMock.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("shows the spec version for the server's TPMVersion enum name", async () => {
    fetchMock.mockImplementation(
      routeInfo(jsonResponse(200, { code: 200, error: "", success: true, payload: tpmInfo }))
    );

    renderPage();

    expect(await screen.findByText("TPM 2.0")).toBeTruthy();
    expect(screen.getByText("Available")).toBeTruthy();
    expect(screen.queryByText(/VERSION/)).toBeNull();
  });

  it("shows the server error when no TPM is available", async () => {
    fetchMock.mockImplementation(
      routeInfo(jsonResponse(503, { code: 503, error: "tpm service is not available", success: false }))
    );

    renderPage();

    expect(await screen.findByText("tpm service is not available")).toBeTruthy();
    expect(screen.queryByText("Available")).toBeNull();
  });
});
