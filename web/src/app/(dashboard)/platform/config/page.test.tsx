import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ConfigPage from "./page";

// #1825: the configuration page reads GET /api/v1/platform/config and
// /api/v1/platform/config/snapshots through the global fetch, and drives
// reload, snapshot, rollback and delete through POST/DELETE on the same
// prefix. These tests stub fetch, the boundary the browser crosses.

const toast = vi.fn();
vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast }),
}));

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function textResponse(status: number, body: string): Response {
  return new Response(body, { status });
}

const configPayload = {
  tree: { server: { port: 8443, name: "edge" }, db: { password: "••••" } },
  sources: [{ path: "/etc/platform/config.yaml", format: "yaml" }],
  generated_at: "2026-11-12T00:00:00Z",
  secrets_hidden: true,
  redacted_keys: ["db.password"],
};

const snapshot = {
  id: "snap-1",
  created_at: "2026-11-11T00:00:00Z",
  reason: "pre-reload",
  actor: "admin",
  size_bytes: 512,
};

type Route = (url: string, init?: RequestInit) => Response | undefined;

describe("ConfigPage", () => {
  const fetchMock = vi.fn<typeof fetch>();
  let routes: Route[] = [];

  function route(r: Route) {
    routes.push(r);
  }

  function defaultRoutes(opts: { config?: Response; snapshots?: Response } = {}) {
    route((url, init) => {
      if (url === "/api/v1/platform/config" && (init?.method ?? "GET") === "GET") {
        return opts.config ?? jsonResponse(200, { payload: configPayload });
      }
      if (url === "/api/v1/platform/config/snapshots" && (init?.method ?? "GET") === "GET") {
        return opts.snapshots ?? jsonResponse(200, { payload: { snapshots: [snapshot] } });
      }
      return undefined;
    });
  }

  beforeEach(() => {
    routes = [];
    toast.mockReset();
    fetchMock.mockReset();
    fetchMock.mockImplementation((input, init) => {
      const url = String(input);
      for (const r of [...routes].reverse()) {
        const res = r(url, init);
        if (res) return Promise.resolve(res);
      }
      return Promise.resolve(textResponse(404, "not found"));
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("shows the sources, the redacted count, the snapshots and the tree", async () => {
    defaultRoutes();
    render(<ConfigPage />);

    expect(await screen.findByText("/etc/platform/config.yaml")).toBeTruthy();
    expect(screen.getByText("yaml")).toBeTruthy();
    expect(screen.getByText(/1 secret\s+redacted/)).toBeTruthy();
    expect(screen.getByText("snap-1")).toBeTruthy();
    expect(screen.getByText("pre-reload")).toBeTruthy();
    expect(screen.getByText("admin")).toBeTruthy();
    expect(screen.getByText("512")).toBeTruthy();
    expect(screen.getByText(/"port": 8443/)).toBeTruthy();
  });

  it("accepts a bare tree without the payload envelope", async () => {
    defaultRoutes({
      config: jsonResponse(200, { ...configPayload, redacted_keys: ["a", "b"] }),
      snapshots: jsonResponse(200, { snapshots: [] }),
    });
    render(<ConfigPage />);

    expect(await screen.findByText("/etc/platform/config.yaml")).toBeTruthy();
    expect(screen.getByText(/2 secrets\s+redacted/)).toBeTruthy();
    expect(screen.getByText(/No snapshots yet/)).toBeTruthy();
  });

  it("says no file is loaded when there are no sources and hides the redaction badge", async () => {
    defaultRoutes({
      config: jsonResponse(200, {
        payload: { ...configPayload, sources: [], secrets_hidden: false },
      }),
    });
    render(<ConfigPage />);

    expect(await screen.findByText("No config file is currently loaded.")).toBeTruthy();
    expect(screen.queryByText(/redacted/)).toBeNull();
  });

  it("shows the HTTP error when the configuration cannot be loaded", async () => {
    defaultRoutes({ config: textResponse(500, "boom") });
    render(<ConfigPage />);

    expect(
      await screen.findByText("Failed to load configuration: HTTP 500: boom"),
    ).toBeTruthy();
    expect(screen.queryByText("Sources")).toBeNull();
    expect((screen.getByText("Download").closest("button") as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows a network error message when fetch rejects", async () => {
    defaultRoutes();
    route((url) => {
      if (url === "/api/v1/platform/config") throw new Error("network down");
      return undefined;
    });
    render(<ConfigPage />);

    expect(await screen.findByText("Failed to load configuration: network down")).toBeTruthy();
  });

  it("treats a failed snapshot listing as non-fatal", async () => {
    defaultRoutes({ snapshots: textResponse(503, "no store") });
    render(<ConfigPage />);

    expect(await screen.findByText("/etc/platform/config.yaml")).toBeTruthy();
    expect(screen.getByText(/No snapshots yet/)).toBeTruthy();
    expect(screen.queryByText(/Failed to load/)).toBeNull();
  });

  it("filters the tree by key, case-insensitively", async () => {
    defaultRoutes();
    render(<ConfigPage />);
    await screen.findByText("/etc/platform/config.yaml");

    fireEvent.change(screen.getByPlaceholderText(/Filter by key/), {
      target: { value: "PORT" },
    });

    const pre = screen.getByText(/"port": 8443/);
    expect(pre.textContent).not.toContain("password");
    expect(pre.textContent).not.toContain("edge");
  });

  it("shows an empty object when the filter matches no key", async () => {
    defaultRoutes();
    render(<ConfigPage />);
    await screen.findByText("/etc/platform/config.yaml");

    fireEvent.change(screen.getByPlaceholderText(/Filter by key/), {
      target: { value: "nomatch" },
    });

    expect(screen.getByText("{}")).toBeTruthy();
  });

  it("reloads and reports the section count and the pre-reload snapshot", async () => {
    defaultRoutes();
    route((url, init) =>
      url === "/api/v1/platform/config/reload" && init?.method === "POST"
        ? jsonResponse(200, { payload: { sections: ["server", "db"], pre_reload_snapshot: "snap-2" } })
        : undefined,
    );
    render(<ConfigPage />);
    await screen.findByText("/etc/platform/config.yaml");

    fireEvent.click(screen.getByText("Reload"));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Configuration reloaded",
        description: "Refreshed 2 sections. Pre-reload snapshot: snap-2",
      }),
    );
  });

  it("reloads without a snapshot id", async () => {
    defaultRoutes();
    route((url, init) =>
      url === "/api/v1/platform/config/reload" && init?.method === "POST"
        ? jsonResponse(200, { sections: ["server"] })
        : undefined,
    );
    render(<ConfigPage />);
    await screen.findByText("/etc/platform/config.yaml");

    fireEvent.click(screen.getByText("Reload"));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Configuration reloaded",
        description: "Refreshed 1 top-level sections",
      }),
    );
  });

  it("reports a failed reload as a destructive toast", async () => {
    defaultRoutes();
    route((url, init) =>
      url === "/api/v1/platform/config/reload" && init?.method === "POST"
        ? textResponse(409, "busy")
        : undefined,
    );
    render(<ConfigPage />);
    await screen.findByText("/etc/platform/config.yaml");

    fireEvent.click(screen.getByText("Reload"));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Reload failed",
        description: "HTTP 409: busy",
        variant: "destructive",
      }),
    );
  });

  it("captures a snapshot with the prompted reason", async () => {
    defaultRoutes();
    vi.spyOn(window, "prompt").mockReturnValue("before upgrade");
    route((url, init) =>
      url === "/api/v1/platform/config/snapshots" && init?.method === "POST"
        ? jsonResponse(200, { payload: { id: "snap-9" } })
        : undefined,
    );
    render(<ConfigPage />);
    await screen.findByText("/etc/platform/config.yaml");

    fireEvent.click(screen.getByText("Snapshot"));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Snapshot captured", description: "snap-9" }),
    );
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ reason: "before upgrade" });
  });

  it("falls back to the manual reason when the prompt is cancelled, and reports a failure", async () => {
    defaultRoutes();
    vi.spyOn(window, "prompt").mockReturnValue(null);
    route((url, init) =>
      url === "/api/v1/platform/config/snapshots" && init?.method === "POST"
        ? textResponse(503, "store not configured")
        : undefined,
    );
    render(<ConfigPage />);
    await screen.findByText("/etc/platform/config.yaml");

    fireEvent.click(screen.getByText("Snapshot"));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Snapshot failed",
        description: "HTTP 503: store not configured",
        variant: "destructive",
      }),
    );
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ reason: "manual" });
  });

  it("does not roll back when the operator declines", async () => {
    defaultRoutes();
    vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<ConfigPage />);
    await screen.findByText("snap-1");

    fireEvent.click(screen.getByTitle("Roll back to this snapshot"));

    expect(window.confirm).toHaveBeenCalled();
    expect(fetchMock.mock.calls.some(([u]) => String(u).endsWith("/rollback"))).toBe(false);
  });

  it("rolls back to the snapshot and reports the pre-rollback snapshot", async () => {
    defaultRoutes();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    route((url, init) =>
      url === "/api/v1/platform/config/snapshots/snap-1/rollback" && init?.method === "POST"
        ? jsonResponse(200, { payload: { pre_rollback_snapshot: "snap-3" } })
        : undefined,
    );
    render(<ConfigPage />);
    await screen.findByText("snap-1");

    fireEvent.click(screen.getByTitle("Roll back to this snapshot"));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Rolled back",
        description: "Pre-rollback snapshot: snap-3",
      }),
    );
  });

  it("reports a failed rollback", async () => {
    defaultRoutes();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    route((url) =>
      url.endsWith("/rollback") ? textResponse(404, "unknown snapshot") : undefined,
    );
    render(<ConfigPage />);
    await screen.findByText("snap-1");

    fireEvent.click(screen.getByTitle("Roll back to this snapshot"));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Rollback failed",
        description: "HTTP 404: unknown snapshot",
        variant: "destructive",
      }),
    );
  });

  it("deletes a snapshot after confirmation", async () => {
    defaultRoutes();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    route((url, init) =>
      url === "/api/v1/platform/config/snapshots/snap-1" && init?.method === "DELETE"
        ? new Response(null, { status: 204 })
        : undefined,
    );
    render(<ConfigPage />);
    await screen.findByText("snap-1");

    fireEvent.click(screen.getByTitle("Delete snapshot"));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Snapshot deleted", description: "snap-1" }),
    );
  });

  it("does not delete when the operator declines, and reports a failed delete", async () => {
    defaultRoutes();
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    route((url, init) =>
      init?.method === "DELETE" && url.startsWith("/api/v1/platform/config/snapshots/")
        ? textResponse(500, "disk full")
        : undefined,
    );
    render(<ConfigPage />);
    await screen.findByText("snap-1");

    fireEvent.click(screen.getByTitle("Delete snapshot"));
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === "DELETE")).toBe(false);

    confirm.mockReturnValue(true);
    fireEvent.click(screen.getByTitle("Delete snapshot"));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Delete failed",
        description: "HTTP 500: disk full",
        variant: "destructive",
      }),
    );
  });

  it("downloads the tree as platform-config.json", async () => {
    defaultRoutes();
    const createObjectURL = vi.fn(() => "blob:config");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    render(<ConfigPage />);
    await screen.findByText("/etc/platform/config.yaml");

    fireEvent.click(screen.getByText("Download"));

    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(click).toHaveBeenCalledTimes(1);
    expect((click.mock.instances[0] as unknown as HTMLAnchorElement).download).toBe(
      "platform-config.json",
    );
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:config");
  });
});
