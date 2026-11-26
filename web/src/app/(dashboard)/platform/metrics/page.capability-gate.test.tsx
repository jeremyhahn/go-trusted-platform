import * as React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the platform metrics page reads the metrics, system and health
// endpoints through usePlatform (network boundary, mocked here) only when the
// server offers each, and gates Retry, Refresh and auto-refresh on the
// metrics read.

const { platform, toast, capability, caps } = vi.hoisted(() => ({
  platform: { getMetrics: vi.fn(), getSystemInfo: vi.fn(), getHealth: vi.fn() },
  toast: vi.fn(),
  capability: vi.fn(),
  caps: { loading: false },
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  usePlatform: () => platform,
  useToast: () => ({ toast }),
}));

// #2033 item 5: Gated and the page read the server's capabilities through this hook.
vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: caps.loading, error: undefined, capability }),
}));

import PlatformMetricsPage from "./page";

const METRICS_OP = "GET /api/v1/platform/metrics";
const SYSTEM_OP = "GET /api/v1/platform/system";
const HEALTH_OP = "GET /api/v1/platform/health";
const REASON = "blocked: integration";

function offExcept(off: string[]) {
  capability.mockImplementation((op: string) => (off.includes(op) ? { enabled: false, reason: REASON } : { enabled: true }));
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole("button", { name }) as HTMLButtonElement;
}

function expectWithheld(el: HTMLElement, op?: string) {
  expect((el as HTMLButtonElement).disabled).toBe(true);
  expect(el.getAttribute("title")).toBe(REASON);
  if (op) {
    expect(el.getAttribute("data-capability-op")).toBe(op);
    expect(el.getAttribute("data-capability-enabled")).toBe("false");
  }
}

beforeEach(() => {
  for (const fn of Object.values(platform)) fn.mockReset();
  platform.getMetrics.mockResolvedValue({
    data: { metrics: { cpuUsagePercent: 10, memoryUsagePercent: 20, diskUsagePercent: 30, activeConnections: 7 } },
  });
  platform.getSystemInfo.mockResolvedValue({
    data: { system: { hostname: "test-host", os: "linux", arch: "amd64", cpuCount: 4, totalMemory: 1024, uptime: 60 } },
  });
  platform.getHealth.mockResolvedValue({
    data: { health: { services: [{ name: "ca-service", healthy: true, latencyMs: 2 }] } },
  });
  toast.mockReset();
  caps.loading = false;
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
});

afterEach(() => {
  cleanup();
});

describe("PlatformMetricsPage capability gate", () => {
  it("shows the not-enabled card with the server's reason and does not read the metrics when GET /api/v1/platform/metrics is not offered", async () => {
    offExcept([METRICS_OP]);
    render(<PlatformMetricsPage />);

    const card = await screen.findByTestId("platform-metrics-not-enabled");
    expect(card.textContent).toContain(REASON);
    expect(platform.getMetrics).not.toHaveBeenCalled();
    expect(screen.queryByText("Loading metrics...")).toBeNull();
    expectWithheld(button("Refresh"), METRICS_OP);
    const toggle = screen.getByRole("switch") as HTMLButtonElement;
    expect(toggle.disabled).toBe(true);
    expect(toggle.getAttribute("title")).toBe(REASON);
  });

  it("shows the loading state and reads nothing while the capabilities load", async () => {
    caps.loading = true;
    offExcept([METRICS_OP, SYSTEM_OP, HEALTH_OP]);
    render(<PlatformMetricsPage />);

    expect(await screen.findByText("Loading metrics...")).toBeTruthy();
    expect(screen.queryByTestId("platform-metrics-not-enabled")).toBeNull();
    expect(platform.getMetrics).not.toHaveBeenCalled();
    expect(platform.getSystemInfo).not.toHaveBeenCalled();
    expect(platform.getHealth).not.toHaveBeenCalled();
  });

  it("does not read the system info or the health when their ops are not offered, and still shows the metrics", async () => {
    offExcept([SYSTEM_OP, HEALTH_OP]);
    render(<PlatformMetricsPage />);

    expect(await screen.findByText("Resource Usage")).toBeTruthy();
    expect(platform.getMetrics).toHaveBeenCalled();
    expect(platform.getSystemInfo).not.toHaveBeenCalled();
    expect(platform.getHealth).not.toHaveBeenCalled();
    expect(screen.queryByText("test-host")).toBeNull();
    expect(screen.queryByText("Service Health")).toBeNull();
    expect(button("Refresh").disabled).toBe(false);
  });

  it("reads every endpoint and leaves the controls enabled when the server offers them", async () => {
    render(<PlatformMetricsPage />);

    expect(await screen.findByText("test-host")).toBeTruthy();
    expect(await screen.findByText("Service Health")).toBeTruthy();
    expect(capability).toHaveBeenCalledWith(METRICS_OP);
    expect(capability).toHaveBeenCalledWith(SYSTEM_OP);
    expect(capability).toHaveBeenCalledWith(HEALTH_OP);
    expect(screen.queryByTestId("platform-metrics-not-enabled")).toBeNull();
    const refresh = button("Refresh");
    expect(refresh.disabled).toBe(false);
    expect(refresh.getAttribute("data-capability-enabled")).toBe("true");
    expect((screen.getByRole("switch") as HTMLButtonElement).disabled).toBe(false);
  });
});
