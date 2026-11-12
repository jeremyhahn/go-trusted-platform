import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import TimeSeriesPage from "./page";

// #1826: the time series page shows its sample metrics, runs an aggregation
// over the range and bucket the operator picks, deletes a metric's data and
// explains metric creation. The client is a stable fake so the real
// useMutation hook runs against it.

const ts = { aggregate: vi.fn(), query: vi.fn(), deleteRange: vi.fn() };
const client = { quicBaaSTimeSeries: ts };
const toast = vi.fn();
const toastResult = { toast };

// The SDK answers with an ApiResponse: data on success, error on refusal.
const ok = (data: unknown) => ({ data });
const refused = (message: string) => ({ error: { code: "REFUSED", message } });

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  usePlatformClient: () => client,
  useToast: () => toastResult,
}));

// The Radix menu's portal does not settle in jsdom, so row menus render inline.
vi.mock("@/components/ui/dropdown-menu", async (importOriginal) => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Item = ({ children, onClick }: { children?: React.ReactNode; onClick?: () => void }) => (
    <button type="button" role="menuitem" onClick={onClick}>
      {children}
    </button>
  );
  return {
    ...(await importOriginal<typeof import("@/components/ui/dropdown-menu")>()),
    DropdownMenu: Pass,
    DropdownMenuTrigger: Pass,
    DropdownMenuContent: Pass,
    DropdownMenuItem: Item,
  };
});

// The Radix select needs pointer capture jsdom lacks, so it renders as a
// native select over the same items; the page's values and handlers are kept.
vi.mock("@/components/ui/select", () => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Select = ({ value, onValueChange, children }: { value?: string; onValueChange?: (v: string) => void; children?: React.ReactNode }) => (
    <select value={value} onChange={(e) => onValueChange?.(e.target.value)}>
      {children}
    </select>
  );
  const Item = ({ value, children }: { value: string; children?: React.ReactNode }) => <option value={value}>{children}</option>;
  return { Select, SelectTrigger: () => null, SelectValue: () => null, SelectContent: Pass, SelectItem: Item };
});

function rowFor(name: string): HTMLElement {
  const row = screen.getByText(name).closest("tr");
  if (!row) throw new Error(`no table row for ${name}`);
  return row;
}

function stat(title: string): string {
  const card = screen.getByText(title).parentElement?.parentElement;
  return card?.querySelector(".text-2xl")?.textContent?.trim() ?? "";
}

function results(n: number) {
  return Array.from({ length: n }, (_, i) => ({
    bucketStart: Date.UTC(2026, 10, 1, i),
    values: { avg: i === 0 ? null : i + 0.5 },
  }));
}

async function openQueryFor(metric: string) {
  fireEvent.click(within(rowFor(metric)).getByRole("menuitem", { name: /Query Data/ }));
  return (await screen.findByLabelText("Metric Name")) as HTMLInputElement;
}

describe("TimeSeriesPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    ts.aggregate.mockResolvedValue(ok({ results: results(12), executionTimeMs: 5 }));
    ts.deleteRange.mockResolvedValue(ok({ deletedCount: 7 }));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("shows the sample metrics with their type, unit, retention and label count", async () => {
    render(<TimeSeriesPage />);
    const cpu = within(await screen.findByText("cpu.usage").then(() => rowFor("cpu.usage")));
    expect(cpu.getByText("gauge")).toBeTruthy();
    expect(cpu.getByText("percent")).toBeTruthy();
    expect(cpu.getByText("30d")).toBeTruthy();
    expect(cpu.getByText("1 label")).toBeTruthy();
    expect(within(rowFor("requests.total")).getByText("counter")).toBeTruthy();
    expect(within(rowFor("requests.total")).getByText("90d")).toBeTruthy();
    expect(within(rowFor("request.latency")).getByText("histogram")).toBeTruthy();
  });

  it("counts the metrics by type", async () => {
    render(<TimeSeriesPage />);
    await screen.findByText("cpu.usage");
    expect(stat("Total Metrics")).toBe("4");
    expect(stat("Counters")).toBe("1");
    expect(stat("Gauges")).toBe("2");
    expect(stat("Histograms")).toBe("1");
  });

  it("refuses to query without a metric name", async () => {
    render(<TimeSeriesPage />);
    fireEvent.click(screen.getByRole("button", { name: /Query Data/ }));
    fireEvent.change(await screen.findByLabelText("Metric Name"), { target: { value: " " } });
    fireEvent.click(screen.getByRole("button", { name: "Run Query" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "Metric name is required" })),
    );
    expect(ts.aggregate).not.toHaveBeenCalled();
    expect(ts.query).not.toHaveBeenCalled();
  });

  it("aggregates the metric of the row over the range, by hourly average by default", async () => {
    render(<TimeSeriesPage />);
    await screen.findByText("cpu.usage");
    const metric = await openQueryFor("cpu.usage");
    expect(metric.value).toBe("cpu.usage");
    fireEvent.change(screen.getByLabelText("Start Time"), { target: { value: "2026-11-01T00:00" } });
    fireEvent.change(screen.getByLabelText("End Time"), { target: { value: "2026-11-02T00:00" } });
    fireEvent.click(screen.getByRole("button", { name: "Run Query" }));
    await waitFor(() =>
      expect(ts.aggregate).toHaveBeenCalledWith({
        metric: "cpu.usage",
        startTime: new Date("2026-11-01T00:00").getTime(),
        endTime: new Date("2026-11-02T00:00").getTime(),
        bucket: "HOUR",
        aggregations: [{ function: "AVG" }],
      }),
    );
    expect(ts.query).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Aggregation completed", description: "12 buckets returned" }));
  });

  it("shows the first ten buckets, a null value and how many more there are", async () => {
    render(<TimeSeriesPage />);
    await screen.findByText("cpu.usage");
    await openQueryFor("memory.used");
    fireEvent.click(screen.getByRole("button", { name: "Run Query" }));
    expect(await screen.findByText("12 buckets, 5ms execution time")).toBeTruthy();
    expect(screen.getByText("null")).toBeTruthy();
    expect(screen.getByText("9.50")).toBeTruthy();
    expect(screen.queryByText("10.50")).toBeNull();
    expect(screen.getByText("... and 2 more")).toBeTruthy();
  });

  it("uses the aggregation and bucket the operator picks", async () => {
    render(<TimeSeriesPage />);
    fireEvent.click(screen.getByRole("button", { name: /Query Data/ }));
    fireEvent.change(await screen.findByLabelText("Metric Name"), { target: { value: "requests.total" } });
    fireEvent.change(screen.getByDisplayValue("Average"), { target: { value: "SUM" } });
    fireEvent.change(screen.getByDisplayValue("Hour"), { target: { value: "DAY" } });
    fireEvent.click(screen.getByRole("button", { name: "Run Query" }));
    await waitFor(() =>
      expect(ts.aggregate).toHaveBeenCalledWith(
        expect.objectContaining({ metric: "requests.total", bucket: "DAY", aggregations: [{ function: "SUM" }] }),
      ),
    );
  });

  it("reports no buckets when the aggregation returns none", async () => {
    ts.aggregate.mockResolvedValue(ok({ executionTimeMs: 1 }));
    render(<TimeSeriesPage />);
    await screen.findByText("cpu.usage");
    await openQueryFor("cpu.usage");
    fireEvent.click(screen.getByRole("button", { name: "Run Query" }));
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "0 buckets returned" })));
    expect(screen.queryByText("Aggregation Result")).toBeNull();
  });

  it("reports a refused aggregation", async () => {
    ts.aggregate.mockResolvedValue(refused("unknown metric"));
    render(<TimeSeriesPage />);
    await screen.findByText("cpu.usage");
    await openQueryFor("cpu.usage");
    fireEvent.click(screen.getByRole("button", { name: "Run Query" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Aggregation failed", description: "unknown metric" })),
    );
    expect(screen.queryByText("Aggregation Result")).toBeNull();
  });

  it("deletes all of a metric's data only after confirmation", async () => {
    vi.stubGlobal("confirm", vi.fn().mockReturnValueOnce(false).mockReturnValue(true));
    render(<TimeSeriesPage />);
    await screen.findByText("cpu.usage");
    const del = () => within(rowFor("request.latency")).getByRole("menuitem", { name: /Delete Data/ });
    fireEvent.click(del());
    expect(ts.deleteRange).not.toHaveBeenCalled();
    const before = Date.now();
    fireEvent.click(del());
    await waitFor(() => expect(ts.deleteRange).toHaveBeenCalledTimes(1));
    const call = ts.deleteRange.mock.calls[0][0] as { metric: string; startTime: number; endTime: number };
    expect(call.metric).toBe("request.latency");
    expect(call.startTime).toBe(0);
    expect(call.endTime).toBeGreaterThanOrEqual(before);
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Data deleted", description: "7 data points deleted" })));
  });

  it("reports zero deleted points when the count is absent, and a refused delete", async () => {
    vi.stubGlobal("confirm", vi.fn(() => true));
    ts.deleteRange.mockResolvedValueOnce(ok({})).mockResolvedValueOnce(refused("retention lock"));
    render(<TimeSeriesPage />);
    await screen.findByText("cpu.usage");
    fireEvent.click(within(rowFor("cpu.usage")).getByRole("menuitem", { name: /Delete Data/ }));
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "0 data points deleted" })));
    fireEvent.click(within(rowFor("cpu.usage")).getByRole("menuitem", { name: /Delete Data/ }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Delete failed", description: "retention lock" })),
    );
  });

  it("explains that metrics are created on insert and closes the dialog", async () => {
    render(<TimeSeriesPage />);
    fireEvent.click(screen.getByRole("button", { name: /Create Metric/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Got It" }));
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Coming Soon" })));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Got It" })).toBeNull());
  });
});
