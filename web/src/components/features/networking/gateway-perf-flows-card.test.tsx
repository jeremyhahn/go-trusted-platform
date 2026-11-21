import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient, GatewayService } from "trusted-platform-sdk";

import { GatewayPerfFlowsCard } from "./gateway-perf-flows-card";

// #2052: the card drives POST /api/v1/gateway/perf/flows through the real SDK
// GatewayService; only fetch and the session are stubbed.

const fetchMock = vi.fn<typeof fetch>();
const gatewayService = new GatewayService(
  new ApiClient({ baseUrl: "https://platform.test/api", fetch: fetchMock, retry: { maxRetries: 0 } })
);
const auth: { current: { user: { roles: string[] } } } = { current: { user: { roles: ["admin"] } } };

vi.mock("@/hooks", () => ({
  useGateway: () => gatewayService,
  useOptionalAuth: () => auth.current,
}));

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function openDialog() {
  await act(async () => screen.getByTestId("perf-flows-run").click());
}

describe("GatewayPerfFlowsCard", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    auth.current = { user: { roles: ["admin"] } };
  });

  afterEach(() => {
    cleanup();
  });

  it("a non-admin sees the benchmark disabled with its reason", () => {
    auth.current = { user: { roles: ["user"] } };
    render(<GatewayPerfFlowsCard />);

    expect((screen.getByTestId("perf-flows-run") as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByTestId("perf-flows-admin-only").textContent).toBe(
      "Requires the admin role: the benchmark installs switch flows."
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("the dialog states the temporary flows and when they expire", async () => {
    render(<GatewayPerfFlowsCard />);
    await openDialog();

    const dialog = screen.getByTestId("perf-flows-dialog");
    expect(screen.getByText("Install temporary switch flows?")).toBeTruthy();
    const text = dialog.textContent ?? "";
    for (const want of [
      "1000 temporary drop flows",
      "table 250",
      "deletes them when the run ends",
      "expires any left behind within 60 seconds",
    ]) {
      expect(text).toContain(want);
    }
    // The server bounds only its delete attempt; the hard timeout is what
    // guarantees expiry (#2179 Codex).
    expect(text).not.toContain("within 30 seconds");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("cancel closes the dialog and sends nothing", async () => {
    render(<GatewayPerfFlowsCard />);
    await openDialog();

    await act(async () => screen.getByTestId("perf-flows-cancel").click());

    expect(screen.queryByTestId("perf-flows-dialog")).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("confirm posts one run and shows the result", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        code: 200,
        success: true,
        payload: { installed: 1000, durationNs: "2500000", flowsPerSecond: 400000, batched: true, bridge: "br-int" },
      })
    );
    render(<GatewayPerfFlowsCard />);
    await openDialog();

    await act(async () => screen.getByTestId("perf-flows-confirm").click());

    const result = await screen.findByTestId("perf-flows-result");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("https://platform.test/api/v1/gateway/perf/flows");
    expect((init as RequestInit).method).toBe("POST");
    expect(JSON.parse(String((init as RequestInit).body))).toEqual({ count: 1000, batch: true });
    const text = result.textContent ?? "";
    expect(text).toContain("1000");
    expect(text).toContain("br-int");
    expect(text).toContain("2.5");
  });

  it("a refused run shows the server message and can run again", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(503, { code: 503, error: "perf service not configured", success: false, payload: null })
    );
    render(<GatewayPerfFlowsCard />);
    await openDialog();

    await act(async () => screen.getByTestId("perf-flows-confirm").click());

    const error = await screen.findByTestId("perf-flows-error");
    expect(error.textContent).toContain("perf service not configured");
    expect((screen.getByTestId("perf-flows-run") as HTMLButtonElement).disabled).toBe(false);
  });

  it("a failed teardown shows the server message and the hard timeout", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(500, {
        code: 500,
        error: "perf operation failed: perf: flow teardown on br-int failed: boom",
        success: false,
        payload: null,
      })
    );
    render(<GatewayPerfFlowsCard />);
    await openDialog();

    await act(async () => screen.getByTestId("perf-flows-confirm").click());

    const error = await screen.findByTestId("perf-flows-error");
    const text = error.textContent ?? "";
    expect(text).toContain("flow teardown on br-int failed");
    expect(text).toContain("expires any left behind within 60 seconds");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
