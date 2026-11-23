import * as React from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import TenantsPage from "./page";

// Codex round 1 on #2146: a late save answer for tenant A must never leave
// the editor targeting A with tenant B's name (or B with A's).

const tenantA = { id: "t-a", name: "Alpha" };
const tenantB = { id: "t-b", name: "Beta" };

const tenantsHook = {
  tenants: [tenantA, tenantB],
  page: 1,
  pageCount: 1,
  setPage: vi.fn(),
  isLoading: false,
  error: null,
  refetch: vi.fn(),
  getTenant: vi.fn(),
  createTenant: vi.fn(),
  updateTenant: vi.fn(),
  deleteTenant: vi.fn(),
};
const toast = vi.fn();
// #2033 item 5: Gated reads the server's capabilities through this hook.
const capability = vi.fn();

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useIAMTenants: () => tenantsHook,
  useToast: () => ({ toast }),
}));
vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: false, error: undefined, capability }),
}));

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

beforeEach(() => {
  vi.clearAllMocks();
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
  tenantsHook.getTenant.mockImplementation(async (id: string) => ({
    data: { tenant: id === tenantA.id ? tenantA : tenantB },
  }));
});

afterEach(() => cleanup());

async function viewTenantA() {
  fireEvent.click(screen.getByRole("button", { name: "View tenant t-a" }));
  await waitFor(() => expect(screen.getByTestId("tenant-detail")).toBeTruthy());
  await waitFor(() =>
    expect((screen.getByLabelText("New name") as HTMLInputElement).value).toBe("Alpha"),
  );
}

function saveAs(name: string) {
  fireEvent.change(screen.getByLabelText("New name"), { target: { value: name } });
  fireEvent.click(screen.getByRole("button", { name: "Save tenant" }));
}

describe("TenantsPage selection", () => {
  it("a late save answer for tenant A does not replace tenant B's editor", async () => {
    render(<TenantsPage />);
    await viewTenantA();

    const update = deferred<{ data: { tenant: typeof tenantA } }>();
    tenantsHook.updateTenant.mockReturnValue(update.promise);
    saveAs("Alpha 2");
    expect(tenantsHook.updateTenant).toHaveBeenCalledWith({ tenantId: "t-a", name: "Alpha 2" });

    fireEvent.click(screen.getByRole("button", { name: "View tenant t-b" }));
    await act(async () => {
      update.resolve({ data: { tenant: { id: "t-a", name: "Alpha 2" } } });
      await update.promise;
    });

    await waitFor(() => expect(screen.getByRole("button", { name: "Save tenant" })).toBeTruthy());
    const detail = screen.getByTestId("tenant-detail");
    const input = screen.getByLabelText("New name") as HTMLInputElement;
    expect(detail.textContent).toContain("t-a");
    expect(input.value).toBe("Alpha 2");
  });

  it("View and Delete buttons are disabled while a save is pending", async () => {
    render(<TenantsPage />);
    await viewTenantA();

    const update = deferred<{ data: { tenant: typeof tenantA } }>();
    tenantsHook.updateTenant.mockReturnValue(update.promise);
    saveAs("Alpha 2");

    for (const id of ["t-a", "t-b"]) {
      expect((screen.getByRole("button", { name: `View tenant ${id}` }) as HTMLButtonElement).disabled).toBe(true);
      expect((screen.getByRole("button", { name: `Delete tenant ${id}` }) as HTMLButtonElement).disabled).toBe(true);
    }

    await act(async () => {
      update.resolve({ data: { tenant: { id: "t-a", name: "Alpha 2" } } });
      await update.promise;
    });
    await waitFor(() =>
      expect((screen.getByRole("button", { name: "View tenant t-b" }) as HTMLButtonElement).disabled).toBe(false),
    );
  });
});

function offering(off: Record<string, string>) {
  capability.mockImplementation((op: string) =>
    op in off ? { enabled: false, reason: off[op] } : { enabled: true },
  );
}

describe("TenantsPage capability gate", () => {
  it("withholds Create tenant with the server's reason when POST /api/v1/iam/tenants is not offered", () => {
    offering({ "POST /api/v1/iam/tenants": "not-configured: iam" });
    render(<TenantsPage />);
    fireEvent.change(screen.getByLabelText("Tenant ID"), { target: { value: "t-c" } });
    fireEvent.change(screen.getByLabelText("Tenant name"), { target: { value: "Gamma" } });

    const create = screen.getByRole("button", { name: /Create tenant/ }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    expect(create.getAttribute("title")).toBe("not-configured: iam");
    expect(create.getAttribute("data-capability-op")).toBe("POST /api/v1/iam/tenants");
    expect(create.getAttribute("data-capability-enabled")).toBe("false");
    fireEvent.click(create);
    expect(tenantsHook.createTenant).not.toHaveBeenCalled();
  });

  it("withholds View, Save tenant and Delete when the server does not offer the tenant reads and writes", async () => {
    offering({
      "DELETE /api/v1/iam/tenants/{tenant}": "unimplemented",
      "PUT /api/v1/iam/tenants/{tenant}": "unimplemented",
    });
    render(<TenantsPage />);

    for (const id of ["t-a", "t-b"]) {
      const del = screen.getByRole("button", { name: `Delete tenant ${id}` }) as HTMLButtonElement;
      expect(del.disabled).toBe(true);
      expect(del.getAttribute("data-capability-op")).toBe("DELETE /api/v1/iam/tenants/{tenant}");
      expect(del.getAttribute("title")).toBe("unimplemented");
    }

    const view = screen.getByRole("button", { name: "View tenant t-a" }) as HTMLButtonElement;
    expect(view.disabled).toBe(false);
    expect(view.getAttribute("data-capability-op")).toBe("GET /api/v1/iam/tenants/{tenant}");
    fireEvent.click(view);
    await waitFor(() => expect(screen.getByTestId("tenant-detail")).toBeTruthy());
    fireEvent.change(screen.getByLabelText("New name"), { target: { value: "Alpha 2" } });

    const save = screen.getByRole("button", { name: "Save tenant" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    expect(save.getAttribute("data-capability-op")).toBe("PUT /api/v1/iam/tenants/{tenant}");
    fireEvent.click(save);
    expect(tenantsHook.updateTenant).not.toHaveBeenCalled();
  });

  it("asks the gate for each tenant op and leaves the controls enabled when the server offers them", () => {
    render(<TenantsPage />);
    for (const op of [
      "POST /api/v1/iam/tenants",
      "GET /api/v1/iam/tenants/{tenant}",
      "DELETE /api/v1/iam/tenants/{tenant}",
    ]) {
      expect(capability).toHaveBeenCalledWith(op);
    }

    fireEvent.click(screen.getByRole("button", { name: "Delete tenant t-b" }));
    const confirm = screen.getByRole("button", { name: "Delete tenant" });
    expect(confirm.getAttribute("data-capability-op")).toBe("DELETE /api/v1/iam/tenants/{tenant}");
    expect(confirm.getAttribute("data-capability-enabled")).toBe("true");
  });
});
