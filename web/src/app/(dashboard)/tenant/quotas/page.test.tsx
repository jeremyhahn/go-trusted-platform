import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import TenantQuotasPage from "./page";

// The page calls useApi twice per render: the quotas first, the usage second.
// The hooks are stubbed so each state can be forced and the fetchers and
// options the page passes can be asserted.

type ApiResult = {
  data: unknown;
  isLoading: boolean;
  error: { message: string } | null;
  refetch: ReturnType<typeof vi.fn>;
};
type ApiCall = {
  fetcher: () => unknown;
  deps: unknown[];
  opts: { enabled?: boolean };
};

const state = {
  auth: { tenantId: "tenant-1" as string | null, isLoading: false },
  quotas: null as unknown as ApiResult,
  usage: null as unknown as ApiResult,
  calls: [] as ApiCall[],
};

const tenantService = { getQuotas: vi.fn(), getUsage: vi.fn() };

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => state.auth,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useTenant: () => tenantService,
  useApi: (fetcher: ApiCall["fetcher"], deps: unknown[], opts: ApiCall["opts"]) => {
    state.calls.push({ fetcher, deps, opts });
    return state.calls.length % 2 === 1 ? state.quotas : state.usage;
  },
}));

function result(data: unknown = null): ApiResult {
  return { data, isLoading: false, error: null, refetch: vi.fn().mockResolvedValue(undefined) };
}

function lastCalls(): { quotas: ApiCall; usage: ApiCall } {
  const n = state.calls.length;
  return { quotas: state.calls[n - 2], usage: state.calls[n - 1] };
}

const quotas = {
  compute: { maxVms: 10, maxContainers: 20, maxVcpus: 16, maxMemoryMb: 32768 },
  network: { maxBridges: 4, maxPorts: 100, maxBandwidthMbps: 1000 },
  storage: { maxVolumesGb: 500, maxSnapshots: 10 },
};
// Compute averages vCPU 50% and memory 50% (disk has no limit): Healthy.
// Network averages bridges 100% and ports 100%: Critical.
// Storage averages volumes 80% and snapshots 70%: Warning.
const usage = {
  tenantId: "tenant-1",
  vms: 5,
  containers: 2,
  vcpus: 8,
  memoryMb: 16384,
  diskGb: 7,
  bridges: 4,
  ports: 100,
  bandwidthMbps: 250,
  volumes: 400,
  snapshots: 7,
  timestamp: "2026-03-15T12:00:00Z",
};

function withData(q: unknown = quotas, u: unknown = usage) {
  state.quotas = result(q);
  state.usage = result({ usage: u });
}

// The usage summary text of a summary card: "<pct>%".
function summary(title: string): string {
  const card = screen.getByText(title).closest(".rounded-lg");
  if (!card) throw new Error(`no card for ${title}`);
  return card.textContent ?? "";
}

beforeEach(() => {
  state.auth = { tenantId: "tenant-1", isLoading: false };
  state.quotas = result();
  state.usage = result();
  state.calls = [];
  tenantService.getQuotas.mockReset();
  tenantService.getUsage.mockReset();
});

afterEach(() => {
  cleanup();
});

describe("TenantQuotasPage queries", () => {
  it("fetches quotas and usage for the tenant once auth has settled", () => {
    render(<TenantQuotasPage />);
    const calls = lastCalls();
    for (const call of [calls.quotas, calls.usage]) {
      expect(call.deps).toEqual(["tenant-1"]);
      expect(call.opts.enabled).toBe(true);
    }
    void calls.quotas.fetcher();
    void calls.usage.fetcher();
    expect(tenantService.getQuotas).toHaveBeenCalledWith("tenant-1");
    expect(tenantService.getUsage).toHaveBeenCalledWith("tenant-1");
  });

  it.each([
    ["no tenant", { tenantId: null, isLoading: false }],
    ["auth loading", { tenantId: "tenant-1", isLoading: true }],
  ])("disables both queries with %s", (_label, auth) => {
    state.auth = auth;
    render(<TenantQuotasPage />);
    const calls = lastCalls();
    expect(calls.quotas.opts.enabled).toBe(false);
    expect(calls.usage.opts.enabled).toBe(false);
  });

  it("passes an empty tenant id to the fetchers without a tenant", () => {
    state.auth = { tenantId: null, isLoading: false };
    render(<TenantQuotasPage />);
    void lastCalls().quotas.fetcher();
    void lastCalls().usage.fetcher();
    expect(tenantService.getQuotas).toHaveBeenCalledWith("");
    expect(tenantService.getUsage).toHaveBeenCalledWith("");
  });
});

describe("TenantQuotasPage states", () => {
  it.each([
    ["quotas", "quota fetch failed", null, "quota fetch failed"],
    ["usage", null, "usage fetch failed", "usage fetch failed"],
    ["both, preferring the quota error", "quota first", "usage second", "quota first"],
  ])("shows the %s error and retries both queries", async (_label, qErr, uErr, shown) => {
    withData();
    if (qErr) state.quotas.error = { message: qErr };
    if (uErr) state.usage.error = { message: uErr };
    render(<TenantQuotasPage />);
    expect(screen.getByText("Error loading quotas")).toBeTruthy();
    expect(screen.getByText(shown)).toBeTruthy();
    expect(screen.queryByText("Compute Usage")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /retry/i }));
    expect(state.quotas.refetch).toHaveBeenCalledTimes(1);
    expect(state.usage.refetch).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["the quotas are loading", () => { state.quotas.isLoading = true; }, true],
    ["the usage is loading", () => { state.usage.isLoading = true; }, true],
    ["auth is loading", () => { state.auth.isLoading = true; }, false],
    ["there are no quotas", () => { state.quotas = result(null); }, false],
    ["the usage response has no usage", () => { state.usage = result({}); }, false],
    ["there is no usage response", () => { state.usage = result(null); }, false],
  ])("shows the skeleton when %s", (_label, setup, refreshDisabled) => {
    withData();
    setup();
    render(<TenantQuotasPage />);
    expect(screen.queryByText("Compute Usage")).toBeNull();
    expect(screen.queryByText("Quota Limits Reference")).toBeNull();
    const refresh = screen.getByRole("button", { name: /refresh/i }) as HTMLButtonElement;
    expect(refresh.disabled).toBe(refreshDisabled);
  });

  it("refreshes both queries from the header", () => {
    withData();
    render(<TenantQuotasPage />);
    fireEvent.click(screen.getByRole("button", { name: /refresh/i }));
    expect(state.quotas.refetch).toHaveBeenCalledTimes(1);
    expect(state.usage.refetch).toHaveBeenCalledTimes(1);
  });
});

describe("TenantQuotasPage usage", () => {
  it("averages each summary over the limits that are set and labels its status", () => {
    withData();
    render(<TenantQuotasPage />);
    expect(summary("Compute Usage")).toMatch(/50%.*Healthy/);
    expect(summary("Network Usage")).toMatch(/100%.*Critical/);
    expect(summary("Storage Usage")).toMatch(/75%.*Warning/);
  });

  it("caps an over-quota dimension at 100% in the summary", () => {
    withData(quotas, { ...usage, vcpus: 64, memoryMb: 0 });
    render(<TenantQuotasPage />);
    // vCPU 400% capped to 100, memory 0%: average 50.
    expect(summary("Compute Usage")).toMatch(/50%/);
  });

  it("lists each resource as used / limit unit, memory in whole GB", () => {
    withData();
    render(<TenantQuotasPage />);
    for (const text of [
      "5 / 10 VMs",
      "2 / 20 containers",
      "8 / 16 cores",
      "16 / 32 GB",
      "7 / 0 GB",
      "4 / 4 bridges",
      "100 / 100 ports",
      "250 / 1000 Mbps",
      "400 / 500 GB",
      "7 / 10 snapshots",
    ]) {
      expect(screen.getByText(text)).toBeTruthy();
    }
  });

  it.each([
    ["5 / 10 VMs", "text-green-500"],
    ["7 / 0 GB", "text-green-500"],
    ["400 / 500 GB", "text-yellow-500"],
    ["4 / 4 bridges", "text-destructive"],
  ])("colours %s by its usage", (text, colour) => {
    withData();
    render(<TenantQuotasPage />);
    expect(screen.getByText(text).className).toContain(colour);
  });

  it.each([
    [74, "text-green-500"],
    [75, "text-yellow-500"],
    [89, "text-yellow-500"],
    [90, "text-destructive"],
    [250, "text-destructive"],
  ])("colours %i of 100 ports at the thresholds", (ports, colour) => {
    withData(quotas, { ...usage, ports });
    render(<TenantQuotasPage />);
    expect(screen.getByText(`${ports} / 100 ports`).className).toContain(colour);
  });

  it("lists the quota limits for reference", () => {
    withData();
    render(<TenantQuotasPage />);
    const value = (label: string) => screen.getByText(label).nextElementSibling?.textContent;
    expect(value("Max VMs")).toBe("10");
    expect(value("Max Containers")).toBe("20");
    expect(value("Max vCPUs")).toBe("16");
    expect(value("Max Memory")).toBe("32 GB");
    expect(value("Max Disk")).toBe("0 GB");
    expect(value("Max Bridges")).toBe("4");
    expect(value("Max Ports")).toBe("100");
    expect(value("Max Bandwidth")).toBe("1000 Mbps");
    expect(value("Max Volumes")).toBe("500 GB");
    expect(value("Max Snapshots")).toBe("10");
    expect(screen.getByText(/Last updated:/)).toBeTruthy();
    expect(screen.getByRole("link", { name: /Back to Tenant Overview/ }).getAttribute("href")).toBe("/tenant");
  });

  it("treats missing quota and usage fields as zero without dividing by zero", () => {
    withData({}, { tenantId: "tenant-1" });
    render(<TenantQuotasPage />);
    for (const title of ["Compute Usage", "Network Usage", "Storage Usage"]) {
      expect(summary(title)).toMatch(/0%.*Healthy/);
      expect(summary(title)).not.toMatch(/NaN/);
    }
    expect(screen.getByText("0 / 0 VMs")).toBeTruthy();
    expect(screen.getByText("0 / 0 snapshots")).toBeTruthy();
    expect(screen.getByText("Max VMs").nextElementSibling?.textContent).toBe("0");
  });
});
