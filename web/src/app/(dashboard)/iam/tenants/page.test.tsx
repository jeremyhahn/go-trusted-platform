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

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useIAMTenants: () => tenantsHook,
  useToast: () => ({ toast }),
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
