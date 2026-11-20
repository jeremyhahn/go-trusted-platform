import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const svc = {
  listTenants: vi.fn(),
  createTenant: vi.fn(),
  updateTenant: vi.fn(),
  deleteTenant: vi.fn(),
  suspendTenant: vi.fn(),
  resumeTenant: vi.fn(),
  getTenantByName: vi.fn(),
  updateQuotas: vi.fn(),
  checkQuota: vi.fn(),
  syncTenants: vi.fn(),
  getDEKStatus: vi.fn(),
  rotateDEK: vi.fn(),
  initBarrier: vi.fn(),
  unsealBarrier: vi.fn(),
  sealBarrier: vi.fn(),
};

vi.mock("trusted-platform-sdk", () => ({
  useTenant: () => svc,
}));

import { useTenantAdmin } from "./use-tenant-admin";

const ok = <T,>(data: T) => Promise.resolve({ success: true, data });
const fail = (message: string) =>
  Promise.resolve({ success: false, error: { code: "X", message } });

const t1 = { id: "t1", name: "acme", state: "ACTIVE" };

beforeEach(() => {
  Object.values(svc).forEach((f) => f.mockReset());
  svc.listTenants.mockImplementation(() => ok({ tenants: [t1], total: 1 }));
});

async function mounted() {
  const hook = renderHook(() => useTenantAdmin());
  await waitFor(() => expect(hook.result.current.isLoading).toBe(false));
  return hook;
}

describe("useTenantAdmin", () => {
  it("lists tenants through the SDK", async () => {
    const { result } = await mounted();
    expect(svc.listTenants).toHaveBeenCalledTimes(1);
    expect(result.current.tenants).toEqual([t1]);
    expect(result.current.error).toBeNull();
  });

  it("surfaces a list failure as an error", async () => {
    svc.listTenants.mockImplementation(() => fail("denied"));
    const { result } = await mounted();
    expect(result.current.error?.message).toBe("denied");
    expect(result.current.tenants).toEqual([]);
  });

  it("creates a tenant and refetches the list", async () => {
    svc.createTenant.mockImplementation(() =>
      ok({ status: { success: true, message: "" }, tenant: { id: "t2", name: "new", state: "ACTIVE" } })
    );
    const { result } = await mounted();
    let created: unknown;
    await act(async () => {
      created = await result.current.createTenant({ name: "new" });
    });
    expect(svc.createTenant).toHaveBeenCalledWith({ name: "new" });
    expect(created).toEqual({ id: "t2", name: "new", state: "ACTIVE" });
    expect(svc.listTenants).toHaveBeenCalledTimes(2);
  });

  it("rejects when a write fails", async () => {
    svc.deleteTenant.mockImplementation(() => fail("in use"));
    const { result } = await mounted();
    await expect(result.current.deleteTenant("t1")).rejects.toThrow("in use");
  });

  it("updates, deletes, suspends and resumes, refetching each time", async () => {
    svc.updateTenant.mockImplementation(() => ok({ status: { success: true } }));
    svc.deleteTenant.mockImplementation(() => ok({ status: { success: true } }));
    svc.suspendTenant.mockImplementation(() => ok({ status: { success: true } }));
    svc.resumeTenant.mockImplementation(() => ok({ status: { success: true } }));
    const { result } = await mounted();
    await act(async () => {
      await result.current.updateTenant({ tenantId: "t1", displayName: "Acme" });
      await result.current.suspendTenant("t1");
      await result.current.resumeTenant("t1");
      await result.current.deleteTenant("t1");
    });
    expect(svc.updateTenant).toHaveBeenCalledWith({ tenantId: "t1", displayName: "Acme" });
    expect(svc.suspendTenant).toHaveBeenCalledWith("t1");
    expect(svc.resumeTenant).toHaveBeenCalledWith("t1");
    expect(svc.deleteTenant).toHaveBeenCalledWith("t1");
    expect(svc.listTenants).toHaveBeenCalledTimes(5);
  });

  it("looks a tenant up by name", async () => {
    svc.getTenantByName.mockImplementation(() => ok({ tenant: t1 }));
    const { result } = await mounted();
    await expect(result.current.getTenantByName("acme")).resolves.toEqual(t1);
    expect(svc.getTenantByName).toHaveBeenCalledWith("acme");
  });

  it("updates quotas and checks a quota", async () => {
    svc.updateQuotas.mockImplementation(() => ok({ status: { success: true } }));
    svc.checkQuota.mockImplementation(() =>
      ok({ tenantId: "t1", resource: "vms", amount: 1, available: true })
    );
    const { result } = await mounted();
    await result.current.updateQuotas({ tenantId: "t1", compute: { maxVms: 7 } });
    expect(svc.updateQuotas).toHaveBeenCalledWith({ tenantId: "t1", compute: { maxVms: 7 } });
    await expect(
      result.current.checkQuota({ tenantId: "t1", resource: "vms", amount: 1 })
    ).resolves.toMatchObject({ available: true });
  });

  it("syncs tenants", async () => {
    svc.syncTenants.mockImplementation(() => ok({ status: { success: true, message: "synced" } }));
    const { result } = await mounted();
    await expect(result.current.sync()).resolves.toEqual({ success: true, message: "synced" });
  });

  it("reads and rotates the DEK", async () => {
    svc.getDEKStatus.mockImplementation(() => ok({ dekStatus: { tenantId: "t1", version: 3 } }));
    svc.rotateDEK.mockImplementation(() => ok({ tenantId: "t1", oldVersion: 3, newVersion: 4 }));
    const { result } = await mounted();
    await expect(result.current.getDEKStatus("t1")).resolves.toMatchObject({ version: 3 });
    await expect(result.current.rotateDEK("t1")).resolves.toMatchObject({ newVersion: 4 });
    expect(svc.rotateDEK).toHaveBeenCalledWith({ tenantId: "t1" });
  });

  it("initialises, unseals and seals the barrier", async () => {
    const status = { status: { success: true, message: "" } };
    svc.initBarrier.mockImplementation(() => ok(status));
    svc.unsealBarrier.mockImplementation(() => ok(status));
    svc.sealBarrier.mockImplementation(() => ok(status));
    const { result } = await mounted();
    await result.current.initBarrier({ tenantId: "t1", threshold: 1, shares: 1 });
    await result.current.unsealBarrier({ tenantId: "t1", key: "a2V5" });
    await result.current.sealBarrier("t1");
    expect(svc.initBarrier).toHaveBeenCalledWith({ tenantId: "t1", threshold: 1, shares: 1 });
    expect(svc.unsealBarrier).toHaveBeenCalledWith({ tenantId: "t1", key: "a2V5" });
    expect(svc.sealBarrier).toHaveBeenCalledWith("t1");
  });
});
