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
  getQuotas: vi.fn(),
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
  service.getTenant.mockImplementation(() =>
    ok({ tenant: { ...tenant, state: "TENANT_STATE_SUSPENDED" } })
  );
  service.getTenantByName.mockImplementation(() => ok({ tenant }));
  service.deleteTenant.mockImplementation(() => ok({}));
  service.suspendTenant.mockImplementation(() =>
    ok({ tenant: { ...tenant, state: "TENANT_STATE_SUSPENDED" } })
  );
  service.getQuotas.mockImplementation(() =>
    ok({ tenantId: "t1", compute: { maxVms: 2, maxContainers: 5, maxVcpus: 8, maxMemoryMb: 4096 } })
  );
  service.updateQuotas.mockImplementation(() => ok({}));
  service.rotateDEK.mockImplementation(() =>
    ok({ tenantId: "t1", oldVersion: 3, newVersion: 4, timestamp: "2026-11-12T00:00:00Z" })
  );
  service.getDEKStatus.mockImplementation(() =>
    ok({
      dekStatus: {
        path: "tenants/t1/dek",
        version: 4,
        algorithm: "AES-256-GCM",
        createdAt: "2026-11-01T00:00:00Z",
      },
    })
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
    const text = dialog().textContent ?? "";
    expect(text).toContain("changes its state only");
    expect(text).not.toContain("lose access");
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

  it("DEK panel shows no usage the server does not report", async () => {
    await lookUp();
    fireEvent.click(screen.getByRole("button", { name: "Load DEK status" }));
    const panel = await screen.findByTestId("dek-status");
    expect(panel.textContent).toContain("AES-256-GCM");
    expect(panel.textContent).toContain("2026-11-01T00:00:00Z");
    expect(panel.textContent).not.toContain("%");
    expect(screen.getByTestId("dek-usage-note")).toBeTruthy();
  });

  it("save quotas sends the entered limits and keeps the other compute limits", async () => {
    await lookUp();
    fireEvent.change(screen.getByLabelText("Maximum VMs"), { target: { value: "12" } });
    fireEvent.click(screen.getByRole("button", { name: "Save quotas" }));
    expect(await screen.findByText("Quotas updated")).toBeTruthy();
    expect(service.getQuotas).toHaveBeenCalledWith("t1");
    expect(service.updateQuotas).toHaveBeenCalledWith({
      tenantId: "t1",
      compute: { maxVms: 12, maxContainers: 5, maxVcpus: 8, maxMemoryMb: 4096 },
    });
  });

  it("a TENANT_STATE_SUSPENDED tenant offers Resume, not Suspend", async () => {
    service.getTenantByName.mockImplementation(() =>
      ok({ tenant: { ...tenant, state: "TENANT_STATE_SUSPENDED" } })
    );
    await lookUp();
    expect(screen.getByRole("button", { name: "Resume" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Suspend" })).toBeNull();
    expect(screen.getByTestId("tenant-state").textContent).toBe("SUSPENDED");
  });

  it("a failed lookup after a successful one leaves no tenant selected", async () => {
    await lookUp();
    service.getTenantByName.mockImplementationOnce(() =>
      Promise.resolve({ success: false, error: { code: "NOT_FOUND", message: "tenant not found" } })
    );
    fireEvent.change(screen.getByLabelText("Tenant name"), { target: { value: "ghost" } });
    fireEvent.click(screen.getByRole("button", { name: "Look up" }));
    expect((await screen.findByRole("alert")).textContent).toContain("tenant not found");
    expect(screen.queryByTestId("tenant-details")).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete" })).toBeNull();
  });

  it("rotate DEK confirmation says data is not re-encrypted and names the tenant", async () => {
    await lookUp();
    fireEvent.click(screen.getByRole("button", { name: "Rotate DEK" }));
    const text = dialog().textContent ?? "";
    expect(text).not.toContain("re-encrypted with it");
    expect(text).toContain("not re-encrypted");
    expect(text).toContain("acme");
  });

  it("sync shows the failure message when the status reports success=false", async () => {
    service.syncTenants.mockImplementation(() =>
      ok({ status: { success: false, message: "sync completed with errors: boom" } })
    );
    render(<TenantLifecyclePage />);
    fireEvent.click(screen.getByRole("button", { name: "Sync tenants" }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("sync completed with errors: boom");
    expect(screen.queryByText("Tenant sync started")).toBeNull();
  });

  it("sync reports started when the status reports success", async () => {
    service.syncTenants.mockImplementation(() => ok({ status: { success: true, message: "ok" } }));
    render(<TenantLifecyclePage />);
    fireEvent.click(screen.getByRole("button", { name: "Sync tenants" }));
    expect(await screen.findByText("Tenant sync started")).toBeTruthy();
  });
});
