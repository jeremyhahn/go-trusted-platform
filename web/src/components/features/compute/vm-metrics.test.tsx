import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import type { VMMetrics } from "@/types/infrastructure";

import { VMMetricsCard } from "./vm-metrics";

// #1816: VMMetricsCard shows the usage percentages to one decimal with a
// progress bar each, and the network rates to two decimals.

const metrics: VMMetrics = {
  cpuUsagePercent: 42.345,
  memoryUsagePercent: 7,
  diskUsagePercent: 99.96,
  networkInMbps: 1.005,
  networkOutMbps: 120,
};

function progressValues(): (string | null)[] {
  return Array.from(document.querySelectorAll('[role="progressbar"]')).map((el) =>
    el.getAttribute("aria-valuenow")
  );
}

describe("VMMetricsCard", () => {
  afterEach(() => {
    cleanup();
  });

  it("labels every metric", () => {
    render(<VMMetricsCard metrics={metrics} />);
    for (const label of [
      "Performance Metrics",
      "CPU Usage",
      "Memory Usage",
      "Disk Usage",
      "Network In",
      "Network Out",
    ]) {
      expect(screen.getByText(label)).toBeTruthy();
    }
  });

  it("rounds percentages to one decimal and rates to two", () => {
    render(<VMMetricsCard metrics={metrics} />);
    expect(screen.getByText("42.3%")).toBeTruthy();
    expect(screen.getByText("7.0%")).toBeTruthy();
    expect(screen.getByText("100.0%")).toBeTruthy();
    expect(screen.getByText("120.00 Mbps")).toBeTruthy();
    // 1.005 is 1.00499... in binary, so toFixed(2) rounds it down.
    expect(screen.getByText("1.00 Mbps")).toBeTruthy();
  });

  it("draws one progress bar per usage percentage and none for the network", () => {
    render(<VMMetricsCard metrics={metrics} />);
    expect(document.querySelectorAll('[role="progressbar"]')).toHaveLength(3);
  });

  it("shows an idle machine as zeros", () => {
    render(
      <VMMetricsCard
        metrics={{
          cpuUsagePercent: 0,
          memoryUsagePercent: 0,
          diskUsagePercent: 0,
          networkInMbps: 0,
          networkOutMbps: 0,
        }}
      />
    );
    expect(screen.getAllByText("0.0%")).toHaveLength(3);
    expect(screen.getAllByText("0.00 Mbps")).toHaveLength(2);
    expect(progressValues()).toHaveLength(3);
  });

  it("prints an out-of-range reading as given", () => {
    render(
      <VMMetricsCard
        metrics={{ ...metrics, cpuUsagePercent: 250, memoryUsagePercent: -5 }}
      />
    );
    expect(screen.getByText("250.0%")).toBeTruthy();
    expect(screen.getByText("-5.0%")).toBeTruthy();
  });
});
