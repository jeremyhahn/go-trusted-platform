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

function listOf(tenants: Array<Record<string, unknown>>) {
  return { success: true, data: { tenants, total: tenants.length } };
}

vi.mock("@/hooks", () => ({
  useTenant: () => tenantSvc,
}));

// The page loads its list on mount; render inside act so that load settles.
async function renderPage() {
  await act(async () => {
    render(<AdminTenantsPage />);
  });
}

async function askDelete(id: string) {
  await renderPage();
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
    tenantSvc.listTenants.mockResolvedValue(listOf([...initialTenants]));
  });
  afterEach(() => cleanup());

  it("sends no request when Cancel is chosen", async () => {
    await askDelete("t-2");
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    });
    expect(screen.queryByTestId("confirm-dialog")).toBeNull();
    expect(tenantSvc.deleteTenant).not.toHaveBeenCalled();
    // Only the mount load: no refresh.
    expect(tenantSvc.listTenants).toHaveBeenCalledTimes(1);
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
    // Only the mount load: no refresh.
    expect(tenantSvc.listTenants).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("tenant-row-t-1")).toBeTruthy();
    expect(screen.getByTestId("tenant-row-t-2")).toBeTruthy();
  });

  it("refreshes the list after a successful delete", async () => {
    tenantSvc.deleteTenant.mockResolvedValue({ success: true, data: {} });
    tenantSvc.listTenants
      .mockResolvedValueOnce(listOf([...initialTenants]))
      .mockResolvedValueOnce(listOf(initialTenants.filter((t) => t.id !== "t-1")));
    await askDelete("t-1");
    await confirm();
    // The mount load, then one refresh.
    expect(tenantSvc.listTenants).toHaveBeenCalledTimes(2);
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
    tenantSvc.listTenants.mockResolvedValue(listOf([]));
  });
  afterEach(() => cleanup());

  it("keeps the latest result when an earlier lookup succeeds last", async () => {
    const resolvers = deferredLookups();
    tenantSvc.deleteTenant.mockResolvedValue({ success: true, data: {} });
    await renderPage();
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
    await renderPage();
    await search("alpha");
    await search("beta");
    await settle(resolvers.get("beta"), { success: true, data: { tenant: initialTenants[1] } });
    await settle(resolvers.get("alpha"), { success: false, error: { message: "alpha lookup failed" } });

    const result = screen.getByTestId("search-result");
    expect(within(result).getByTestId("tenant-row-t-2")).toBeTruthy();
    expect(screen.getByTestId("action-result").textContent).toBe("");
  });
});

// #2023 Codex r2: the Create tenant form sends exactly the typed name and
// display name, refreshes the list on success, and on a refusal shows the
// error and keeps what was typed.
describe("AdminTenantsPage create", () => {
  async function fillAndCreate(name: string, displayName: string) {
    await act(async () => {
      fireEvent.change(screen.getByLabelText("Name"), { target: { value: name } });
      fireEvent.change(screen.getByLabelText("Display name"), { target: { value: displayName } });
    });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Create" }));
    });
  }

  beforeEach(() => {
    for (const fn of Object.values(tenantSvc)) fn.mockReset();
    tenantSvc.listTenants.mockResolvedValue(listOf([...initialTenants]));
  });
  afterEach(() => cleanup());

  it("sends exactly the typed name and display name", async () => {
    tenantSvc.createTenant.mockResolvedValue({ success: true, data: {} });
    await renderPage();
    await fillAndCreate("gamma", "Gamma Corp");
    expect(tenantSvc.createTenant).toHaveBeenCalledTimes(1);
    expect(tenantSvc.createTenant).toHaveBeenCalledWith({ name: "gamma", displayName: "Gamma Corp" });
  });

  it("refreshes the list and clears the form after a successful create", async () => {
    tenantSvc.createTenant.mockResolvedValue({ success: true, data: {} });
    const created = { id: "t-3", name: "gamma", displayName: "Gamma Corp", state: 1 };
    tenantSvc.listTenants
      .mockResolvedValueOnce(listOf([...initialTenants]))
      .mockResolvedValueOnce(listOf([...initialTenants, created]));
    await renderPage();
    await fillAndCreate("gamma", "Gamma Corp");
    // The mount load, then one refresh.
    expect(tenantSvc.listTenants).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId("action-result").textContent).toBe("Created tenant gamma");
    expect(screen.getByTestId("tenant-row-t-3")).toBeTruthy();
    expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("");
    expect((screen.getByLabelText("Display name") as HTMLInputElement).value).toBe("");
  });

  it("shows the error and keeps the inputs when the create is refused", async () => {
    tenantSvc.createTenant.mockResolvedValue({ success: false, error: { message: "tenant name taken" } });
    await renderPage();
    await fillAndCreate("alpha", "Alpha Again");
    expect(tenantSvc.createTenant).toHaveBeenCalledWith({ name: "alpha", displayName: "Alpha Again" });
    expect(screen.getByTestId("action-result").textContent).toBe("tenant name taken");
    // Only the mount load: no refresh.
    expect(tenantSvc.listTenants).toHaveBeenCalledTimes(1);
    expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("alpha");
    expect((screen.getByLabelText("Display name") as HTMLInputElement).value).toBe("Alpha Again");
  });
});
