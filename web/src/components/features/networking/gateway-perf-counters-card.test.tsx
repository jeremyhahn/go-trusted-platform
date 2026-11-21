import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient, GatewayService } from "trusted-platform-sdk";

import { GatewayPerfCountersCard, parseZone } from "./gateway-perf-counters-card";

// #2052: the card drives GET /api/v1/gateway/perf/datapath and
// GET /api/v1/gateway/perf/conntrack through the real SDK GatewayService;
// only fetch and the session are stubbed.

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

function button(testId: string): HTMLButtonElement {
  return screen.getByTestId(testId) as HTMLButtonElement;
}

describe("parseZone", () => {
  it("parses the zone filter", () => {
    expect(parseZone("")).toBeUndefined();
    expect(parseZone(" 7 ")).toBe(7);
    expect(parseZone("0")).toBe(0);
    expect(parseZone("seven")).toBeNull();
    expect(parseZone("70000")).toBeNull();
    expect(parseZone("-1")).toBeNull();
  });
});

describe("GatewayPerfCountersCard", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    auth.current = { user: { roles: ["admin"] } };
  });

  afterEach(() => {
    cleanup();
  });

  it("a non-admin sees both reads disabled with the reason", () => {
    auth.current = { user: { roles: ["user"] } };
    render(<GatewayPerfCountersCard />);

    expect(button("perf-datapath-load").disabled).toBe(true);
    expect(button("perf-conntrack-load").disabled).toBe(true);
    expect(screen.getByTestId("perf-counters-admin-only").textContent).toBe(
      "Requires the admin role: the counters are an operator view."
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reads the datapath counters", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        code: 200,
        success: true,
        payload: {
          hits: "10",
          misses: "2",
          offloadedFlowCount: "4",
          hwOffloadEnabled: true,
          datapathType: "system",
          bridge: "br-int",
        },
      })
    );
    render(<GatewayPerfCountersCard />);
    fireEvent.change(screen.getByTestId("perf-datapath-bridge"), { target: { value: "br-int" } });

    await act(async () => button("perf-datapath-load").click());

    const result = await screen.findByTestId("perf-datapath-result");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("https://platform.test/api/v1/gateway/perf/datapath?bridge=br-int");
    expect(((init as RequestInit).method ?? "GET").toUpperCase()).toBe("GET");
    const text = result.textContent ?? "";
    expect(text).toContain("system");
    expect(text).toContain("10");
    expect(text).toMatch(/Lost\s*0/);
    expect(text).toContain("Hardware offload: on");
  });

  it("reads the conntrack summary for every zone", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        code: 200,
        success: true,
        payload: { totalEntries: "42", perZone: { "7": "12", "0": "30" } },
      })
    );
    render(<GatewayPerfCountersCard />);

    await act(async () => button("perf-conntrack-load").click());

    const result = await screen.findByTestId("perf-conntrack-result");
    const [url] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("https://platform.test/api/v1/gateway/perf/conntrack");
    const text = result.textContent ?? "";
    expect(text).toContain("Total entries 42");
    const zone0 = text.indexOf("Zone 0: 30");
    const zone7 = text.indexOf("Zone 7: 12");
    expect(zone0).toBeGreaterThanOrEqual(0);
    expect(zone7).toBeGreaterThan(zone0);
  });

  it("keeps Read conntrack disabled for a bad zone", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, { code: 200, success: true, payload: { totalEntries: "1", perZone: { "7": "1" } } })
    );
    render(<GatewayPerfCountersCard />);
    const zone = screen.getByTestId("perf-conntrack-zone");

    fireEvent.change(zone, { target: { value: "seven" } });
    expect(button("perf-conntrack-load").disabled).toBe(true);

    fireEvent.change(zone, { target: { value: "7" } });
    expect(button("perf-conntrack-load").disabled).toBe(false);
    await act(async () => button("perf-conntrack-load").click());

    await screen.findByTestId("perf-conntrack-result");
    const [url] = fetchMock.mock.calls[0];
    expect(String(url).endsWith("?zone=7")).toBe(true);
  });

  it("a refused read shows the server message", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(404, { code: 404, error: "bridge not found", success: false, payload: null })
    );
    render(<GatewayPerfCountersCard />);

    await act(async () => button("perf-datapath-load").click());

    const error = await screen.findByTestId("perf-counters-error");
    expect(error.textContent).toContain("bridge not found");
    expect(button("perf-datapath-load").disabled).toBe(false);
  });
});
