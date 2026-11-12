import * as React from "react";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import TenantLifecyclePage from "./page";

const tenant = {
  id: "t1",
  name: "acme",
  displayName: "Acme",
  state: "ACTIVE",
};

const ok = <T,>(data: T) => Promise.resolve({ success: true, data });

const service = {
  getTenant: vi.fn(),
  getTenantByName: vi.fn(),
  updateTenant: vi.fn(),
  deleteTenant: vi.fn(),
  suspendTenant: vi.fn(),
  resumeTenant: vi.fn(),
  updateQuotas: vi.fn(),
  checkQuota: vi.fn(),
  syncTenants: vi.fn(),
  getDEKStatus: vi.fn(),
  rotateDEK: vi.fn(),
};

vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  useTenant: () => service,
}));

// The Radix portal is replaced by parts that render only while open, so
// the confirm buttons are plain DOM inside a role="dialog" element.
vi.mock("@/components/ui/dialog", () => {
  const Ctx = React.createContext(false);
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  return {
    Dialog: ({ open, children }: { open?: boolean; children?: React.ReactNode }) => (
      <Ctx.Provider value={!!open}>{children}</Ctx.Provider>
    ),
    DialogContent: ({ children }: { children?: React.ReactNode }) =>
      React.useContext(Ctx) ? <div role="dialog">{children}</div> : null,
    DialogHeader: Pass,
    DialogFooter: Pass,
    DialogTitle: Pass,
    DialogDescription: Pass,
  };
});

async function flush() {
  await act(async () => {
    await Promise.resolve();
  });
}

async function lookUp() {
  render(<TenantLifecyclePage />);
  fireEvent.change(screen.getByLabelText("Tenant name"), { target: { value: "acme" } });
  fireEvent.click(screen.getByRole("button", { name: "Look up" }));
  await screen.findByTestId("tenant-details");
}

function dialog() {
  return screen.getByRole("dialog");
}

beforeEach(() => {
  service.getTenant.mockImplementation(() => ok({ tenant: { ...tenant, state: "SUSPENDED" } }));
  service.getTenantByName.mockImplementation(() => ok({ tenant }));
  service.deleteTenant.mockImplementation(() => ok({}));
  service.suspendTenant.mockImplementation(() => ok({ tenant: { ...tenant, state: "SUSPENDED" } }));
  service.updateQuotas.mockImplementation(() => ok({}));
  service.rotateDEK.mockImplementation(() =>
    ok({ tenantId: "t1", oldVersion: 3, newVersion: 4, timestamp: "2026-11-12T00:00:00Z" })
  );
  service.getDEKStatus.mockImplementation(() =>
    ok({ dekStatus: { version: 4, algorithm: "AES-256-GCM", status: "active", usagePercent: 1 } })
  );
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("TenantLifecyclePage", () => {
  it("delete calls deleteTenant only after the confirm button", async () => {
    await lookUp();
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(service.deleteTenant).not.toHaveBeenCalled();
    fireEvent.click(within(dialog()).getByRole("button", { name: "Delete" }));
    await flush();
    expect(service.deleteTenant).toHaveBeenCalledTimes(1);
    expect(service.deleteTenant).toHaveBeenCalledWith("t1");
  });

  it("cancel closes the delete dialog without calling deleteTenant", async () => {
    await lookUp();
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    fireEvent.click(within(dialog()).getByRole("button", { name: "Cancel" }));
    await flush();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(service.deleteTenant).not.toHaveBeenCalled();
  });

  it("suspend asks for confirmation first", async () => {
    await lookUp();
    fireEvent.click(screen.getByRole("button", { name: "Suspend" }));
    expect(service.suspendTenant).not.toHaveBeenCalled();
    fireEvent.click(within(dialog()).getByRole("button", { name: "Suspend" }));
    expect(await screen.findByText("Tenant suspended")).toBeTruthy();
    expect(service.suspendTenant).toHaveBeenCalledTimes(1);
    expect(service.suspendTenant).toHaveBeenCalledWith("t1");
    expect(screen.getByTestId("tenant-state").textContent).toBe("SUSPENDED");
  });

  it("rotate DEK asks for confirmation and shows the new version", async () => {
    await lookUp();
    fireEvent.click(screen.getByRole("button", { name: "Rotate DEK" }));
    expect(service.rotateDEK).not.toHaveBeenCalled();
    fireEvent.click(within(dialog()).getByRole("button", { name: "Rotate" }));
    expect(await screen.findByText("DEK rotated to version 4")).toBeTruthy();
    expect(service.rotateDEK).toHaveBeenCalledTimes(1);
    expect(service.rotateDEK).toHaveBeenCalledWith({ tenantId: "t1" });
    expect(screen.getByTestId("dek-version").textContent).toBe("4");
  });

  it("save quotas sends the entered limits", async () => {
    await lookUp();
    fireEvent.change(screen.getByLabelText("Maximum VMs"), { target: { value: "12" } });
    fireEvent.click(screen.getByRole("button", { name: "Save quotas" }));
    expect(await screen.findByText("Quotas updated")).toBeTruthy();
    expect(service.updateQuotas).toHaveBeenCalledWith({ tenantId: "t1", compute: { maxVms: 12 } });
  });
});
