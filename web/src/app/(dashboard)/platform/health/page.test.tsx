import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import HealthPage from "./page";

// The health page reads platform health, metrics and system info through the
// SDK's usePlatform client and the real useApi. Only the client and the
// toast are mocked; the feature cards render for real.

const ok = <T,>(data: T) => Promise.resolve({ success: true, data });

const platform = {
  getHealth: vi.fn(),
  getMetrics: vi.fn(),
  getSystemInfo: vi.fn(),
};
const toast = vi.fn();

vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  usePlatform: () => platform,
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast }),
}));

const health = {
  health: {
    healthy: true,
    timestamp: "2026-11-12T10:00:00Z",
    services: [
      { name: "ca", healthy: true, latencyMs: 4, lastCheck: "2026-11-12T10:00:00Z" },
      { name: "ntp", healthy: false, status: "degraded", message: "time-unsynced" },
      { name: "dns", healthy: false, message: "resolver timeout" },
    ],
  },
};

describe("HealthPage", () => {
  beforeEach(() => {
    toast.mockReset();
    platform.getHealth.mockReset().mockImplementation(() => ok(health));
    platform.getMetrics.mockReset().mockImplementation(() =>
      ok({
        metrics: {
          cpuUsagePercent: 25,
          memoryUsagePercent: 50,
          diskUsagePercent: 10,
          activeConnections: 7,
        },
      }),
    );
    platform.getSystemInfo
      .mockReset()
      .mockImplementation(() => ok({ system: { num_cpus: 4, total_memory_mb: 8192 } }));
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("shows only the spinner while the health read is pending", () => {
    platform.getHealth.mockImplementation(() => new Promise(() => {}));
    render(<HealthPage />);

    expect(screen.getByText("System Health")).toBeTruthy();
    expect(screen.queryByText("Refresh")).toBeNull();
    expect(screen.queryByText("Services")).toBeNull();
    expect(platform.getHealth).toHaveBeenCalledWith({ includeServices: true });
    expect(platform.getMetrics).toHaveBeenCalledWith({ includeHistory: false });
  });

  it("shows the overall status, connections, resources and every service", async () => {
    render(<HealthPage />);

    expect(await screen.findByText("Services")).toBeTruthy();
    expect(screen.getByText("Healthy")).toBeTruthy();
    await screen.findByText("7 active connections");
    await screen.findByText("25.0% used");
    expect(screen.getByText("50.0% used")).toBeTruthy();
    expect(screen.getByText("10.0% used")).toBeTruthy();
    expect(screen.getByText("ca")).toBeTruthy();
    expect(screen.getByText("ntp")).toBeTruthy();
    expect(screen.getByText("dns")).toBeTruthy();
    expect(screen.getByText(/Last updated:/)).toBeTruthy();
  });

  it("shows a degraded component as degraded with its reason, and a failed one as down", async () => {
    render(<HealthPage />);
    await screen.findByText("Services");

    expect(screen.getByText("Degraded")).toBeTruthy();
    expect(screen.getByText("time-unsynced")).toBeTruthy();
    expect(screen.getByText("resolver timeout")).toBeTruthy();
    expect(screen.getAllByText("Down").length).toBeGreaterThanOrEqual(1);
  });

  it("reads snake_case metrics and the system block nested in the metrics", async () => {
    platform.getHealth.mockImplementation(() =>
      ok({ health: { healthy: false, services: [] } }),
    );
    platform.getMetrics.mockImplementation(() =>
      ok({
        metrics: {
          cpu_usage_percent: 50,
          memory_usage_percent: 25,
          disk_usage_percent: 30,
          active_connections: 3,
          system: { numCpus: 2, totalMemoryMb: 4096 },
        },
      }),
    );
    render(<HealthPage />);

    expect(await screen.findByText("3 active connections")).toBeTruthy();
    expect(screen.getByText("50.0% used")).toBeTruthy();
    expect(screen.getByText("25.0% used")).toBeTruthy();
    expect(screen.getByText("30.0% used")).toBeTruthy();
    expect(screen.getAllByText("Down").length).toBeGreaterThanOrEqual(1);
  });

  it("falls back to zero for missing or non-numeric metrics instead of NaN", async () => {
    platform.getMetrics.mockImplementation(() =>
      ok({ metrics: { cpuUsagePercent: "not-a-number" } }),
    );
    platform.getSystemInfo.mockImplementation(() => ok({}));
    render(<HealthPage />);

    expect(await screen.findByText("0 active connections")).toBeTruthy();
    expect(screen.getAllByText("0.0% used").length).toBe(3);
    expect(screen.queryByText(/NaN/)).toBeNull();
  });

  it("toasts a failed health read and renders no status", async () => {
    platform.getHealth.mockImplementation(() =>
      Promise.resolve({ success: false, error: { message: "health down" } }),
    );
    render(<HealthPage />);

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Error fetching health data",
        description: "health down",
        variant: "destructive",
      }),
    );
    expect(screen.getByText("Refresh")).toBeTruthy();
    expect(screen.queryByText("Services")).toBeNull();
  });

  it("refetches health and metrics on Refresh", async () => {
    render(<HealthPage />);
    await screen.findByText("Services");

    fireEvent.click(screen.getByText("Refresh"));
    await waitFor(() => expect(platform.getHealth).toHaveBeenCalledTimes(2));
    expect(platform.getMetrics).toHaveBeenCalledTimes(2);
    expect(platform.getSystemInfo).toHaveBeenCalledTimes(1);
  });

  it("polls every 30 seconds while auto-refresh is on", async () => {
    render(<HealthPage />);
    await screen.findByText("Services");
    vi.useFakeTimers();

    fireEvent.click(screen.getByRole("switch"));
    await act(async () => {
      vi.advanceTimersByTime(30000);
    });
    expect(platform.getHealth).toHaveBeenCalledTimes(2);
    expect(platform.getMetrics).toHaveBeenCalledTimes(2);

    fireEvent.click(screen.getByRole("switch"));
    await act(async () => {
      vi.advanceTimersByTime(60000);
    });
    expect(platform.getHealth).toHaveBeenCalledTimes(2);
  });
});
