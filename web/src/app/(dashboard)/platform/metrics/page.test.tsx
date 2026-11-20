import * as React from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import MetricsPage from "./page";

// The metrics page reads platform metrics, system info and health through
// the SDK's usePlatform client and the real useApi. Only the client and the
// toast are mocked; the Radix select renders as a native <select>.

const ok = <T,>(data: T) => Promise.resolve({ success: true, data });

const platform = {
  getMetrics: vi.fn(),
  getSystemInfo: vi.fn(),
  getHealth: vi.fn(),
};
const toast = vi.fn();

vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  usePlatform: () => platform,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useToast: () => ({ toast }),
}));

vi.mock("@/components/ui/select", () => {
  const Select = ({
    value,
    onValueChange,
    children,
  }: {
    value?: string;
    onValueChange?: (v: string) => void;
    children?: React.ReactNode;
  }) => (
    <select value={value} onChange={(e) => onValueChange?.(e.target.value)}>
      {children}
    </select>
  );
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const None = () => null;
  const SelectItem = ({ value, children }: { value: string; children?: React.ReactNode }) => (
    <option value={value}>{children}</option>
  );
  return { Select, SelectContent: Pass, SelectTrigger: None, SelectValue: None, SelectItem };
});

const metrics = {
  metrics: {
    cpuUsagePercent: 42.5,
    memoryUsagePercent: 60,
    diskUsagePercent: 95,
    activeConnections: 9,
    requestsPerSecond: 12,
    errorRate: 0.015,
  },
};

const system = {
  system: {
    uptime: 90061,
    hostname: "edge-01",
    os: "linux",
    arch: "amd64",
    cpuCount: 8,
    totalMemory: 17179869184,
  },
};

const health = {
  health: {
    healthy: false,
    services: [
      { name: "quic-baas", healthy: true, latencyMs: 2.345 },
      { name: "dns", healthy: false },
    ],
  },
};

function cardText(title: string): string {
  return screen.getByText(title).closest("div")?.parentElement?.textContent ?? "";
}

describe("MetricsPage", () => {
  beforeEach(() => {
    toast.mockReset();
    platform.getMetrics.mockReset().mockImplementation(() => ok(metrics));
    platform.getSystemInfo.mockReset().mockImplementation(() => ok(system));
    platform.getHealth.mockReset().mockImplementation(() => ok(health));
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("shows the loading state while the metrics read is pending", () => {
    platform.getMetrics.mockImplementation(() => new Promise(() => {}));
    render(<MetricsPage />);

    expect(screen.getByText("Loading metrics...")).toBeTruthy();
    expect(platform.getMetrics).toHaveBeenCalledWith({ includeHistory: false });
    expect(platform.getHealth).toHaveBeenCalledWith({ includeServices: true });
  });

  it("shows the system overview, the resource cards and the service health", async () => {
    render(<MetricsPage />);

    expect(await screen.findByText("Resource Usage")).toBeTruthy();
    await screen.findByText("edge-01");
    expect(screen.getByText("1d 1h 1m")).toBeTruthy();
    expect(screen.getByText(/linux\s+amd64/)).toBeTruthy();
    expect(cardText("CPU Cores")).toContain("8");
    expect(cardText("Connections")).toContain("9");
    expect(cardText("CPU Usage")).toContain("42.5%");
    expect(screen.getByText("8 cores available")).toBeTruthy();
    expect(cardText("Memory Usage")).toContain("60%");
    expect(screen.getByText("16.0 GB total")).toBeTruthy();
    expect(cardText("Disk Usage")).toContain("95%");
    expect(cardText("Request Rate")).toContain("12req/s");
    expect(screen.getByText("Error rate: 1.50%")).toBeTruthy();

    await screen.findByText("Service Health");
    expect(screen.getByText("Quic Baas")).toBeTruthy();
    expect(screen.getByText("2.3 ms")).toBeTruthy();
    expect(screen.getByText("Healthy")).toBeTruthy();
    expect(screen.getByText("Dns")).toBeTruthy();
    expect(screen.getByText("Unhealthy")).toBeTruthy();
    expect(screen.getByText("0.0 ms")).toBeTruthy();
  });

  it("falls back when system info and optional metrics are missing", async () => {
    platform.getMetrics.mockImplementation(() =>
      ok({ metrics: { cpuUsagePercent: 10, memoryUsagePercent: 20 } }),
    );
    platform.getSystemInfo.mockImplementation(() =>
      Promise.resolve({ success: false, error: { message: "no system" } }),
    );
    platform.getHealth.mockImplementation(() => ok({ health: { healthy: true } }));
    render(<MetricsPage />);

    expect(await screen.findByText("Resource Usage")).toBeTruthy();
    expect(screen.getAllByText("N/A").length).toBe(2);
    expect(screen.getByText(/Unknown/)).toBeTruthy();
    expect(screen.getByText("Memory info")).toBeTruthy();
    expect(screen.getByText("0 cores available")).toBeTruthy();
    expect(screen.getByText("Error rate: 0.00%")).toBeTruthy();
    expect(cardText("Connections")).toContain("0");
    expect(screen.queryByText("Service Health")).toBeNull();
  });

  it("renders only the header when the response carries no metrics", async () => {
    platform.getMetrics.mockImplementation(() => ok({}));
    render(<MetricsPage />);

    expect(await screen.findByText("Refresh")).toBeTruthy();
    expect(screen.queryByText("Resource Usage")).toBeNull();
    expect(screen.queryByText("Loading metrics...")).toBeNull();
  });

  it("shows the error state with a retry, and toasts the failure", async () => {
    platform.getMetrics.mockImplementation(() =>
      Promise.resolve({ success: false, error: { message: "metrics unavailable" } }),
    );
    render(<MetricsPage />);

    expect(await screen.findByText("Error Loading Metrics")).toBeTruthy();
    expect(screen.getByText("metrics unavailable")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith({
      title: "Error loading metrics",
      description: "metrics unavailable",
      variant: "destructive",
    });

    platform.getMetrics.mockImplementation(() => ok(metrics));
    fireEvent.click(screen.getByText("Retry"));
    expect(await screen.findByText("Resource Usage")).toBeTruthy();
  });

  it("refetches the metrics on Refresh and keeps the chosen time range", async () => {
    render(<MetricsPage />);
    await screen.findByText("Resource Usage");

    const range = screen.getByRole("combobox") as HTMLSelectElement;
    fireEvent.change(range, { target: { value: "7d" } });
    expect(range.value).toBe("7d");

    fireEvent.click(screen.getByText("Refresh"));
    await waitFor(() => expect(platform.getMetrics).toHaveBeenCalledTimes(2));
    expect(platform.getSystemInfo).toHaveBeenCalledTimes(1);
  });

  it("polls every 10 seconds while auto-refresh is on", async () => {
    render(<MetricsPage />);
    await screen.findByText("Resource Usage");
    vi.useFakeTimers();

    fireEvent.click(screen.getByRole("switch"));
    expect(screen.getByText(/auto-refreshing every 10s/)).toBeTruthy();
    await act(async () => {
      vi.advanceTimersByTime(10000);
    });
    expect(platform.getMetrics).toHaveBeenCalledTimes(2);

    fireEvent.click(screen.getByRole("switch"));
    await act(async () => {
      vi.advanceTimersByTime(30000);
    });
    expect(platform.getMetrics).toHaveBeenCalledTimes(2);
    expect(screen.queryByText(/auto-refreshing/)).toBeNull();
  });
});
