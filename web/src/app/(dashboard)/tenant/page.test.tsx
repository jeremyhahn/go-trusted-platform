import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import TenantPage from "./page";

// The page calls useApi twice per render: the tenant first, the users second.
// The hooks are stubbed so each state can be forced and the fetchers and
// options the page passes can be asserted.

type ApiResult = {
  data: unknown;
  isLoading: boolean;
  error: { message: string } | null;
  refetch: ReturnType<typeof vi.fn>;
};
type ApiCall = {
  fetcher: () => Promise<unknown>;
  deps: unknown[];
  opts?: { onError?: (err: { message: string }) => void };
};

const state = {
  auth: { tenantId: "tenant-1" as string | null, isLoading: false },
  tenant: null as unknown as ApiResult,
  users: null as unknown as ApiResult,
  calls: [] as ApiCall[],
};

const toast = vi.fn();
const tenantService = { getTenant: vi.fn() };
const iam = { listUsers: vi.fn() };

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => state.auth,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useToast: () => ({ toast }),
  useTenant: () => tenantService,
  useIAM: () => iam,
  useApi: (fetcher: ApiCall["fetcher"], deps: unknown[], opts?: ApiCall["opts"]) => {
    state.calls.push({ fetcher, deps, opts });
    return state.calls.length % 2 === 1 ? state.tenant : state.users;
  },
}));

function result(data: unknown = null): ApiResult {
  return { data, isLoading: false, error: null, refetch: vi.fn() };
}

function lastCalls(): { tenant: ApiCall; users: ApiCall } {
  const n = state.calls.length;
  return { tenant: state.calls[n - 2], users: state.calls[n - 1] };
}

const baseTenant = {
  id: "tenant-1",
  name: "acme",
  displayName: "Acme Corp",
  state: "active",
  createdAt: "2026-03-15T12:00:00Z",
};

function withTenant(tenant: Record<string, unknown>, users: unknown[] = []) {
  state.tenant = result({ tenant });
  state.users = result({ users });
}

beforeEach(() => {
  state.auth = { tenantId: "tenant-1", isLoading: false };
  state.tenant = result();
  state.users = result();
  state.calls = [];
  toast.mockReset();
  tenantService.getTenant.mockReset();
  iam.listUsers.mockReset();
});

afterEach(() => {
  cleanup();
});

describe("TenantPage queries", () => {
  it("fetches the tenant and its users by tenant id", () => {
    render(<TenantPage />);
    const { tenant, users } = lastCalls();
    expect(tenant.deps).toEqual(["tenant-1"]);
    expect(users.deps).toEqual(["tenant-1"]);
    void tenant.fetcher();
    void users.fetcher();
    expect(tenantService.getTenant).toHaveBeenCalledWith("tenant-1");
    expect(iam.listUsers).toHaveBeenCalledWith({ tenantId: "tenant-1" });
  });

  it("resolves both fetchers to no data without a tenant, calling nothing", async () => {
    state.auth = { tenantId: null, isLoading: false };
    render(<TenantPage />);
    const { tenant, users } = lastCalls();
    await expect(tenant.fetcher()).resolves.toEqual({ success: true, data: null });
    await expect(users.fetcher()).resolves.toEqual({ success: true, data: null });
    expect(tenantService.getTenant).not.toHaveBeenCalled();
    expect(iam.listUsers).not.toHaveBeenCalled();
  });

  it("toasts a tenant load error", () => {
    render(<TenantPage />);
    lastCalls().tenant.opts!.onError!({ message: "boom" });
    expect(toast).toHaveBeenCalledWith({
      title: "Error loading tenant",
      description: "boom",
      variant: "destructive",
    });
  });
});

describe("TenantPage states", () => {
  it("shows the error and retries the tenant on click", () => {
    state.tenant = { ...result(), error: { message: "tenant service down" } };
    render(<TenantPage />);
    expect(screen.getByText("Error loading tenant")).toBeTruthy();
    expect(screen.getByText("tenant service down")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /retry/i }));
    expect(state.tenant.refetch).toHaveBeenCalledTimes(1);
  });

  it("shows the error even without a tenant id", () => {
    state.auth = { tenantId: null, isLoading: false };
    state.tenant = { ...result(), error: { message: "unauthorised" } };
    render(<TenantPage />);
    expect(screen.getByText("Error loading tenant")).toBeTruthy();
    expect(screen.queryByText("No tenant selected")).toBeNull();
  });

  it("asks to create an organization without a tenant id", () => {
    state.auth = { tenantId: null, isLoading: false };
    render(<TenantPage />);
    expect(screen.getByText("No tenant selected")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Create Organization" })).toBeTruthy();
  });

  it.each([
    ["auth is loading", () => { state.auth.isLoading = true; }],
    ["the tenant is loading", () => { state.tenant.isLoading = true; }],
    ["the users are loading", () => { state.users.isLoading = true; }],
    ["there is no tenant data", () => { state.tenant = result(null); }],
    ["the response has no tenant", () => { state.tenant = result({}); }],
  ])("shows the skeleton when %s", (_label, setup) => {
    withTenant(baseTenant);
    setup();
    render(<TenantPage />);
    expect(screen.queryByText("Acme Corp")).toBeNull();
    expect(screen.queryByText("Total Members")).toBeNull();
  });
});

describe("TenantPage tenant card", () => {
  it("renders the tenant name, state, creation date, plan and member counts", () => {
    withTenant(baseTenant, [{ id: "u1" }, { id: "u2" }, { id: "u3" }]);
    render(<TenantPage />);
    expect(screen.getByText("Acme Corp")).toBeTruthy();
    expect(screen.getByText("active")).toBeTruthy();
    expect(screen.getByText(/Created\s+March 15, 2026/)).toBeTruthy();
    expect(screen.getByText("free")).toBeTruthy();
    expect(screen.getAllByText("3")).toHaveLength(3);
    expect(screen.getByText("Max: 10")).toBeTruthy();
    expect(screen.getByText(/100\s*% active/)).toBeTruthy();
  });

  it("falls back to the name without a display name and to active without a state", () => {
    withTenant({ id: "t", name: "plain-name", createdAt: baseTenant.createdAt });
    render(<TenantPage />);
    expect(screen.getByText("plain-name")).toBeTruthy();
    expect(screen.getByText("active")).toBeTruthy();
  });

  it("shows a non-active state as given", () => {
    withTenant({ ...baseTenant, state: "suspended" });
    render(<TenantPage />);
    expect(screen.getByText("suspended")).toBeTruthy();
  });

  it("shows zero members and zero percent active without users", () => {
    state.tenant = result({ tenant: baseTenant });
    state.users = result(null);
    render(<TenantPage />);
    expect(screen.getByText(/^0\s*% active/)).toBeTruthy();
    expect(screen.getAllByText("0").length).toBeGreaterThanOrEqual(3);
  });

  it.each([
    ["a plan label", { labels: { plan: "pro" } }, "pro"],
    ["a plan label over the quota", { labels: { plan: "free" }, computeQuota: { maxVms: 50 } }, "free"],
    ["more than ten VMs", { computeQuota: { maxVms: 11 } }, "enterprise"],
    ["exactly ten VMs", { computeQuota: { maxVms: 10 } }, "pro"],
    ["more than five VMs", { computeQuota: { maxVms: 6 } }, "pro"],
    ["exactly five VMs", { computeQuota: { maxVms: 5 } }, "free"],
    ["a quota without VMs", { computeQuota: {} }, "free"],
  ])("derives the plan from %s", (_label, extra, plan) => {
    withTenant({ ...baseTenant, ...extra });
    render(<TenantPage />);
    expect(screen.getByText(plan)).toBeTruthy();
  });

  it("takes the member maximum from the vCPU quota", () => {
    withTenant({ ...baseTenant, computeQuota: { maxVcpus: 42 } });
    render(<TenantPage />);
    expect(screen.getByText("Max: 42")).toBeTruthy();
  });

  it("lists enabled features and allowed domains, dropping empty entries", () => {
    withTenant({
      ...baseTenant,
      labels: { allowed_domains: "alpha-domain,,beta-domain," },
      annotations: { features: ",vms,containers" },
    });
    render(<TenantPage />);
    expect(screen.getByText("Enabled Features")).toBeTruthy();
    expect(screen.getByText("vms")).toBeTruthy();
    expect(screen.getByText("containers")).toBeTruthy();
    expect(screen.getByText("Allowed Domains")).toBeTruthy();
    expect(screen.getByText("alpha-domain")).toBeTruthy();
    expect(screen.getByText("beta-domain")).toBeTruthy();
  });

  it.each([
    ["absent", {}],
    ["only separators", { labels: { allowed_domains: ",," }, annotations: { features: "," } }],
    ["empty", { labels: { allowed_domains: "" }, annotations: { features: "" } }],
  ])("hides features and domains when they are %s", (_label, extra) => {
    withTenant({ ...baseTenant, ...extra });
    render(<TenantPage />);
    expect(screen.queryByText("Enabled Features")).toBeNull();
    expect(screen.queryByText("Allowed Domains")).toBeNull();
  });

  it("links to the members, invitations and quotas pages", () => {
    withTenant(baseTenant);
    render(<TenantPage />);
    const href = (name: RegExp) => screen.getByRole("link", { name }).getAttribute("href");
    expect(href(/View All Members/)).toBe("/tenant/members");
    expect(href(/Manage Invitations/)).toBe("/tenant/invitations");
    expect(href(/Resource Quotas/)).toBe("/tenant/quotas");
  });
});
