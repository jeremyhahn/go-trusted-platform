import * as React from "react";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import AdminTenantsPage from "./page";

// #2023 Codex round 4: the tenant list can permanently delete a tenant.
// Cancel sends nothing, Confirm deletes exactly the selected tenant, a
// refusal keeps the row and shows its message, and a success refreshes the
// list.

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => <a href={href}>{children}</a>,
}));

const tenantSvc = vi.hoisted(() => ({
  listTenants: vi.fn(),
  createTenant: vi.fn(),
  getTenantByName: vi.fn(),
  deleteTenant: vi.fn(),
}));

const initialTenants = [
  { id: "t-1", name: "alpha", displayName: "Alpha", state: 1 },
  { id: "t-2", name: "beta", displayName: "Beta", state: 1 },
];

const apiResult = vi.hoisted(() => ({
  data: { tenants: [] as Array<Record<string, unknown>>, total: 0 },
  isLoading: false,
  error: null as Error | null,
  refetch: vi.fn(),
}));

vi.mock("@/hooks", () => ({
  useApi: () => apiResult,
  useTenant: () => tenantSvc,
}));

async function askDelete(id: string) {
  render(<AdminTenantsPage />);
  const row = screen.getByTestId(`tenant-row-${id}`);
  await act(async () => {
    fireEvent.click(within(row).getByRole("button", { name: "Delete" }));
  });
  expect(screen.getByTestId("confirm-dialog")).toBeTruthy();
}

async function confirm() {
  await act(async () => {
    fireEvent.click(screen.getByTestId("confirm-action"));
  });
}

describe("AdminTenantsPage delete", () => {
  beforeEach(() => {
    for (const fn of Object.values(tenantSvc)) fn.mockReset();
    apiResult.data = { tenants: [...initialTenants], total: initialTenants.length };
    apiResult.refetch.mockReset();
    apiResult.refetch.mockResolvedValue(undefined);
  });
  afterEach(() => cleanup());

  it("sends no request when Cancel is chosen", async () => {
    await askDelete("t-2");
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    });
    expect(screen.queryByTestId("confirm-dialog")).toBeNull();
    expect(tenantSvc.deleteTenant).not.toHaveBeenCalled();
    expect(apiResult.refetch).not.toHaveBeenCalled();
    expect(screen.getByTestId("tenant-row-t-2")).toBeTruthy();
  });

  it("deletes exactly the selected tenant on Confirm", async () => {
    tenantSvc.deleteTenant.mockResolvedValue({ success: true, data: {} });
    await askDelete("t-2");
    await confirm();
    expect(tenantSvc.deleteTenant).toHaveBeenCalledTimes(1);
    expect(tenantSvc.deleteTenant).toHaveBeenCalledWith("t-2");
  });

  it("keeps the row and shows the error when the delete fails", async () => {
    tenantSvc.deleteTenant.mockResolvedValue({ success: false, error: { message: "tenant has live VMs" } });
    await askDelete("t-1");
    await confirm();
    expect(tenantSvc.deleteTenant).toHaveBeenCalledWith("t-1");
    expect(screen.getByTestId("action-result").textContent).toBe("tenant has live VMs");
    expect(apiResult.refetch).not.toHaveBeenCalled();
    expect(screen.getByTestId("tenant-row-t-1")).toBeTruthy();
    expect(screen.getByTestId("tenant-row-t-2")).toBeTruthy();
  });

  it("refreshes the list after a successful delete", async () => {
    tenantSvc.deleteTenant.mockResolvedValue({ success: true, data: {} });
    apiResult.refetch.mockImplementation(async () => {
      apiResult.data = { tenants: initialTenants.filter((t) => t.id !== "t-1"), total: 1 };
    });
    await askDelete("t-1");
    await confirm();
    expect(apiResult.refetch).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("action-result").textContent).toBe("Deleted tenant alpha");
    expect(screen.queryByTestId("tenant-row-t-1")).toBeNull();
    expect(screen.getByTestId("tenant-row-t-2")).toBeTruthy();
    expect(screen.getByTestId("tenant-page-info").textContent).toBe("Showing 1-1 of 1");
  });
});

// #2023 Codex round 1: Find stays enabled while a lookup is pending, so a
// superseded lookup that settles last must not replace the latest result.
describe("AdminTenantsPage find by name", () => {
  type Lookup = { success: boolean; data?: { tenant: Record<string, unknown> }; error?: { message: string } };

  function deferredLookups() {
    const resolvers = new Map<string, (r: Lookup) => void>();
    tenantSvc.getTenantByName.mockImplementation(
      (name: string) => new Promise<Lookup>((resolve) => resolvers.set(name, resolve)),
    );
    return resolvers;
  }

  async function search(name: string) {
    await act(async () => {
      fireEvent.change(screen.getByLabelText("Tenant name"), { target: { value: name } });
    });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Find" }));
    });
  }

  async function settle(resolve: ((r: Lookup) => void) | undefined, r: Lookup) {
    await act(async () => {
      resolve?.(r);
    });
  }

  beforeEach(() => {
    for (const fn of Object.values(tenantSvc)) fn.mockReset();
    apiResult.data = { tenants: [], total: 0 };
    apiResult.refetch.mockReset();
    apiResult.refetch.mockResolvedValue(undefined);
  });
  afterEach(() => cleanup());

  it("keeps the latest result when an earlier lookup succeeds last", async () => {
    const resolvers = deferredLookups();
    tenantSvc.deleteTenant.mockResolvedValue({ success: true, data: {} });
    render(<AdminTenantsPage />);
    await search("alpha");
    await search("beta");
    await settle(resolvers.get("beta"), { success: true, data: { tenant: initialTenants[1] } });
    await settle(resolvers.get("alpha"), { success: true, data: { tenant: initialTenants[0] } });

    const result = screen.getByTestId("search-result");
    expect(within(result).getByTestId("tenant-row-t-2")).toBeTruthy();
    expect(within(result).queryByTestId("tenant-row-t-1")).toBeNull();
    await act(async () => {
      fireEvent.click(within(result).getByRole("button", { name: "Delete" }));
    });
    await confirm();
    expect(tenantSvc.deleteTenant).toHaveBeenCalledWith("t-2");
  });

  it("keeps the latest result when an earlier lookup fails last", async () => {
    const resolvers = deferredLookups();
    render(<AdminTenantsPage />);
    await search("alpha");
    await search("beta");
    await settle(resolvers.get("beta"), { success: true, data: { tenant: initialTenants[1] } });
    await settle(resolvers.get("alpha"), { success: false, error: { message: "alpha lookup failed" } });

    const result = screen.getByTestId("search-result");
    expect(within(result).getByTestId("tenant-row-t-2")).toBeTruthy();
    expect(screen.getByTestId("action-result").textContent).toBe("");
  });
});
