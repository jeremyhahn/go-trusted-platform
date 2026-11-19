import * as React from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import EventsPage from "./page";

// The events page builds its stream from GET platform health through the
// SDK's usePlatform client and the real useApi. Only the client and the toast
// are mocked; the Radix select is rendered as a native <select> so jsdom can
// drive the filters.

type Service = {
  name: string;
  healthy: boolean;
  message?: string;
  lastCheck?: string;
  latencyMs?: number;
};

const platform = {
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

function healthWith(services: Service[], timestamp = "2026-11-12T10:00:00Z") {
  return Promise.resolve({ success: true, data: { health: { healthy: true, services, timestamp } } });
}

const services: Service[] = [
  { name: "ca", healthy: true, latencyMs: 3, lastCheck: "2026-11-12T10:00:00Z" },
  { name: "dns", healthy: false, message: "resolver timeout" },
];

function selects() {
  return screen.getAllByRole("combobox") as HTMLSelectElement[];
}

describe("EventsPage", () => {
  beforeEach(() => {
    toast.mockReset();
    platform.getHealth.mockReset();
    platform.getHealth.mockImplementation(() => healthWith(services));
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("shows the loading state while the health read is pending", () => {
    platform.getHealth.mockImplementation(() => new Promise(() => {}));
    render(<EventsPage />);

    expect(screen.getByText("Loading events...")).toBeTruthy();
    expect(platform.getHealth).toHaveBeenCalledWith({ includeServices: true });
  });

  it("turns each service into a healthy or unhealthy event and counts them", async () => {
    render(<EventsPage />);

    expect(await screen.findByText("Service Healthy: ca")).toBeTruthy();
    expect(screen.getByText("Service Unhealthy: dns")).toBeTruthy();
    expect(screen.getByText("Service ca is operating normally")).toBeTruthy();
    expect(screen.getByText("resolver timeout")).toBeTruthy();
    expect(screen.getByText("latencyMs: 3")).toBeTruthy();
    expect(screen.getByText("latencyMs: N/A")).toBeTruthy();
    expect(screen.getByText("2 events matching filters")).toBeTruthy();
    expect(screen.getByText("Total Events").closest("div")?.parentElement?.textContent).toContain("2");
  });

  it("describes an unhealthy service without a message", async () => {
    platform.getHealth.mockImplementation(() => healthWith([{ name: "pxe", healthy: false }]));
    render(<EventsPage />);

    expect(await screen.findByText("Service pxe is experiencing issues")).toBeTruthy();
    expect(screen.getByText("1 event matching filters")).toBeTruthy();
  });

  it("shows the empty state when the platform reports no services", async () => {
    platform.getHealth.mockImplementation(() =>
      Promise.resolve({ success: true, data: { health: { healthy: true } } }),
    );
    render(<EventsPage />);

    expect(await screen.findByText("No events available from platform services")).toBeTruthy();
    expect((screen.getByText("Export").closest("button") as HTMLButtonElement).disabled).toBe(true);
  });

  it("filters by severity and says when no event matches", async () => {
    render(<EventsPage />);
    await screen.findByText("Service Healthy: ca");

    fireEvent.change(selects()[0], { target: { value: "error" } });
    expect(screen.queryByText("Service Healthy: ca")).toBeNull();
    expect(screen.getByText("Service Unhealthy: dns")).toBeTruthy();

    fireEvent.change(selects()[0], { target: { value: "warning" } });
    expect(screen.getByText("No events found")).toBeTruthy();
    expect(screen.getByText("Try adjusting your filters")).toBeTruthy();
  });

  it("filters by category", async () => {
    render(<EventsPage />);
    await screen.findByText("Service Healthy: ca");

    fireEvent.change(selects()[1], { target: { value: "security" } });
    expect(screen.getByText("0 events matching filters")).toBeTruthy();

    fireEvent.change(selects()[1], { target: { value: "service" } });
    expect(screen.getByText("2 events matching filters")).toBeTruthy();
  });

  it("shows the error state with a retry, and toasts the failure", async () => {
    platform.getHealth.mockImplementation(() =>
      Promise.resolve({ success: false, error: { message: "health unavailable" } }),
    );
    render(<EventsPage />);

    expect(await screen.findByText("Error Loading Events")).toBeTruthy();
    expect(screen.getByText("health unavailable")).toBeTruthy();
    expect(toast).toHaveBeenCalledWith({
      title: "Error loading platform events",
      description: "health unavailable",
      variant: "destructive",
    });

    platform.getHealth.mockImplementation(() => healthWith(services));
    fireEvent.click(screen.getByText("Retry"));
    expect(await screen.findByText("Service Healthy: ca")).toBeTruthy();
  });

  it("refetches on Refresh", async () => {
    render(<EventsPage />);
    await screen.findByText("Service Healthy: ca");

    fireEvent.click(screen.getByText("Refresh"));
    await waitFor(() => expect(platform.getHealth).toHaveBeenCalledTimes(2));
  });

  it("starts and stops the stream, polling every 5 seconds while it runs", async () => {
    render(<EventsPage />);
    await screen.findByText("Service Healthy: ca");
    vi.useFakeTimers();

    fireEvent.click(screen.getByText("Start Stream"));
    expect(toast).toHaveBeenCalledWith({
      title: "Streaming started",
      description: "Now receiving live events",
    });
    expect(screen.getByText(/Live streaming enabled/)).toBeTruthy();
    expect((screen.getByText("Refresh").closest("button") as HTMLButtonElement).disabled).toBe(true);

    await act(async () => {
      vi.advanceTimersByTime(5000);
    });
    expect(platform.getHealth).toHaveBeenCalledTimes(2);

    fireEvent.click(screen.getByText("Stop Stream"));
    expect(toast).toHaveBeenCalledWith({
      title: "Streaming stopped",
      description: "Live event stream has been paused",
    });
    await act(async () => {
      vi.advanceTimersByTime(10000);
    });
    expect(platform.getHealth).toHaveBeenCalledTimes(2);
  });

  it("exports the filtered events as JSON", async () => {
    const createObjectURL = vi.fn(() => "blob:events");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    render(<EventsPage />);
    await screen.findByText("Service Healthy: ca");

    fireEvent.change(selects()[0], { target: { value: "success" } });
    fireEvent.click(screen.getByText("Export"));

    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect((click.mock.instances[0] as unknown as HTMLAnchorElement).download).toMatch(
      /^platform-events-\d{4}-\d{2}-\d{2}\.json$/,
    );
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:events");
    expect(toast).toHaveBeenCalledWith({
      title: "Events exported",
      description: "Exported 1 events to JSON file",
    });
  });
});
