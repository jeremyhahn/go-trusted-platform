import * as React from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import LogsPage from "./page";

// The logs page reads GET /api/v1/platform/logs and /logs/services through
// the global fetch and streams /logs/stream through EventSource. These tests
// stub both, the boundaries the browser crosses; the Radix select renders as
// a native <select> so jsdom can drive it.

const toast = vi.fn();
vi.mock("@/hooks/use-toast", () => ({
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

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function textResponse(status: number, body: string): Response {
  return new Response(body, { status });
}

const entry = {
  time: "2026-11-12T10:00:00Z",
  level: "INFO",
  msg: "certificate issued",
  service: "ca",
  attrs: { serial: "01" },
};

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  onmessage: ((e: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;
  constructor(
    public url: string,
    public init?: EventSourceInit,
  ) {
    FakeEventSource.instances.push(this);
  }
  close() {
    this.closed = true;
  }
}

type Route = (url: string) => Response | undefined;

describe("LogsPage", () => {
  const fetchMock = vi.fn<typeof fetch>();
  let routes: Route[] = [];

  function route(r: Route) {
    routes.push(r);
  }

  function defaultRoutes(opts: { logs?: () => Response; services?: () => Response } = {}) {
    route((url) => {
      if (url === "/api/v1/platform/logs/services") {
        return opts.services?.() ?? jsonResponse(200, { payload: { services: ["ca", "dns"] } });
      }
      if (url.startsWith("/api/v1/platform/logs?")) {
        return opts.logs?.() ?? jsonResponse(200, { payload: { entries: [entry] } });
      }
      return undefined;
    });
  }

  function logCalls(): URLSearchParams[] {
    return fetchMock.mock.calls
      .map(([u]) => String(u))
      .filter((u) => u.startsWith("/api/v1/platform/logs?"))
      .map((u) => new URLSearchParams(u.split("?")[1]));
  }

  beforeEach(() => {
    routes = [];
    toast.mockReset();
    FakeEventSource.instances = [];
    fetchMock.mockReset();
    fetchMock.mockImplementation((input) => {
      const url = String(input);
      for (const r of [...routes].reverse()) {
        let res: Response | undefined;
        try {
          res = r(url);
        } catch (e) {
          return Promise.reject(e);
        }
        if (res) return Promise.resolve(res);
      }
      return Promise.resolve(textResponse(404, "not found"));
    });
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("EventSource", FakeEventSource);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("loads the entries and the service list, querying the last hour by default", async () => {
    defaultRoutes();
    render(<LogsPage />);

    expect(await screen.findByText("certificate issued")).toBeTruthy();
    expect(await screen.findByRole("option", { name: "dns" })).toBeTruthy();
    const q = logCalls()[0];
    expect(q.get("limit")).toBe("200");
    expect(q.get("since")).not.toBeNull();
    expect(q.get("level")).toBeNull();
    expect(q.get("service")).toBeNull();
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ credentials: "include" });
  });

  it("accepts bare bodies without the payload envelope", async () => {
    defaultRoutes({
      logs: () => jsonResponse(200, { entries: [{ ...entry, msg: "bare entry" }] }),
      services: () => jsonResponse(200, { services: ["pxe"] }),
    });
    render(<LogsPage />);

    expect(await screen.findByText("bare entry")).toBeTruthy();
    expect(await screen.findByRole("option", { name: "pxe" })).toBeTruthy();
  });

  it("shows the empty message when no entry matches", async () => {
    defaultRoutes({ logs: () => jsonResponse(200, {}) });
    render(<LogsPage />);

    expect(await screen.findByText("No log entries match the current filters.")).toBeTruthy();
    expect((screen.getByText("Export").closest("button") as HTMLButtonElement).disabled).toBe(true);
  });

  it("toasts the HTTP error when the logs cannot be read", async () => {
    defaultRoutes({ logs: () => textResponse(500, "store offline") });
    render(<LogsPage />);

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Failed to load logs",
        description: "HTTP 500: store offline",
        variant: "destructive",
      }),
    );
  });

  it("toasts a network error and treats a failed service list as non-fatal", async () => {
    defaultRoutes({ services: () => textResponse(503, "no") });
    route((url) => {
      if (url.startsWith("/api/v1/platform/logs?")) throw new Error("network down");
      return undefined;
    });
    render(<LogsPage />);

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Failed to load logs",
        description: "network down",
        variant: "destructive",
      }),
    );
    expect(screen.getAllByRole("option").map((o) => o.textContent)).toContain("All services");
    expect(screen.queryByRole("option", { name: "ca" })).toBeNull();
  });

  it("re-queries with the level, service, search and time range filters", async () => {
    defaultRoutes();
    render(<LogsPage />);
    await screen.findByRole("option", { name: "dns" });

    fireEvent.click(screen.getByText("ERROR"));
    await waitFor(() => expect(logCalls().at(-1)?.get("level")).toBe("ERROR"));

    const [service, range] = screen.getAllByRole("combobox") as HTMLSelectElement[];
    fireEvent.change(service, { target: { value: "dns" } });
    await waitFor(() => expect(logCalls().at(-1)?.get("service")).toBe("dns"));

    fireEvent.change(screen.getByPlaceholderText(/Substring filter/), {
      target: { value: "issued" },
    });
    await waitFor(() => expect(logCalls().at(-1)?.get("grep")).toBe("issued"));

    fireEvent.change(range, { target: { value: "all" } });
    await waitFor(() => expect(logCalls().at(-1)?.get("since")).toBeNull());

    fireEvent.change(range, { target: { value: "5m" } });
    await waitFor(() => expect(logCalls().at(-1)?.get("since")).not.toBeNull());

    fireEvent.click(screen.getByText("ALL"));
    await waitFor(() => expect(logCalls().at(-1)?.get("level")).toBeNull());
  });

  it("re-reads the logs on Refresh", async () => {
    defaultRoutes();
    render(<LogsPage />);
    await screen.findByText("certificate issued");

    fireEvent.click(screen.getByText("Refresh"));
    await waitFor(() => expect(logCalls().length).toBe(2));
  });

  it("streams entries over SSE, ignores malformed lines and closes on stop", async () => {
    defaultRoutes();
    render(<LogsPage />);
    await screen.findByText("certificate issued");

    fireEvent.click(screen.getByText("Start Stream"));
    expect(screen.getByText("Live streaming enabled")).toBeTruthy();
    const es = FakeEventSource.instances[0];
    expect(es.url).toMatch(/^\/api\/v1\/platform\/logs\/stream\?/);
    expect(es.init).toEqual({ withCredentials: true });

    act(() => {
      es.onmessage?.({ data: JSON.stringify({ ...entry, msg: "streamed line" }) });
      es.onmessage?.({ data: "{not json" });
      es.onerror?.();
    });
    expect(screen.getByText("streamed line")).toBeTruthy();
    expect(screen.getByText("certificate issued")).toBeTruthy();

    fireEvent.click(screen.getByText("Stop Stream"));
    expect(es.closed).toBe(true);
    expect(screen.queryByText("Live streaming enabled")).toBeNull();
  });

  it("closes an open stream on unmount", async () => {
    defaultRoutes();
    const { unmount } = render(<LogsPage />);
    await screen.findByText("certificate issued");
    fireEvent.click(screen.getByText("Start Stream"));

    unmount();
    expect(FakeEventSource.instances[0].closed).toBe(true);
  });

  it("exports the shown entries as JSON", async () => {
    defaultRoutes();
    const createObjectURL = vi.fn(() => "blob:logs");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    render(<LogsPage />);
    await screen.findByText("certificate issued");

    fireEvent.click(screen.getByText("Export"));

    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect((click.mock.instances[0] as unknown as HTMLAnchorElement).download).toMatch(
      /^logs-\d{4}-\d{2}-\d{2}\.json$/,
    );
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:logs");
    expect(toast).toHaveBeenCalledWith({
      title: "Logs exported",
      description: "Logs downloaded as JSON.",
    });
  });
});
