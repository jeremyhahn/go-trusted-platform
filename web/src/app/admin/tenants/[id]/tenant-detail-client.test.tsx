import * as React from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2023 Codex round 1: TenantGRPCServer.Sync reports a failed run in
// status.success=false inside an HTTP 200 response, so the page must read the
// in-band status rather than the SDK's outer success flag.

const syncTenants = vi.fn();

vi.mock("next/navigation", () => ({
  useParams: () => ({ id: "t-1" }),
  usePathname: () => "/admin/tenants/t-1/",
}));

const tenantSvc = vi.hoisted(() => ({
  suspendTenant: vi.fn(),
  rotateDEK: vi.fn(),
  sealBarrier: vi.fn(),
  updateQuotas: vi.fn(),
}));

const apiResult = vi.hoisted(() => ({
  data: {
    tenant: {
      tenantId: "t-1",
      name: "Acme",
      state: "ACTIVE",
      computeQuota: { maxVms: 4, maxContainers: 7, maxVcpus: 8, maxMemoryMb: 1024 },
    },
  },
  isLoading: false,
  error: null,
  refetch: () => Promise.resolve(),
}));

vi.mock("@/hooks", () => ({
  useApi: () => apiResult,
  useTenant: () => ({ syncTenants, ...tenantSvc }),
}));

import TenantDetailClient from "./tenant-detail-client";

async function clickSync() {
  render(<TenantDetailClient />);
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Sync tenants" }));
  });
}

describe("TenantDetailClient sync", () => {
  beforeEach(() => syncTenants.mockReset());
  afterEach(() => cleanup());

  it("shows the in-band failure message when the sync run fails", async () => {
    syncTenants.mockResolvedValue({
      success: true,
      data: { status: { success: false, message: "sync backend down" } },
    });
    await clickSync();
    const result = screen.getByTestId("action-result");
    expect(result.textContent).toContain("sync backend down");
    expect(result.textContent).not.toContain("Tenants synced");
  });

  it("reports success when the sync run succeeds", async () => {
    syncTenants.mockResolvedValue({
      success: true,
      data: { status: { success: true, message: "" } },
    });
    await clickSync();
    expect(screen.getByTestId("action-result").textContent).toBe("Tenants synced");
  });
});

// #2023 Codex round 2: the destructive actions ask first, Cancel sends
// nothing, Confirm sends one request for this page's tenant, and a refusal
// shows its message. A quota save keeps the limits that were not edited.
describe("TenantDetailClient actions", () => {
  beforeEach(() => {
    for (const fn of Object.values(tenantSvc)) fn.mockReset();
  });
  afterEach(() => cleanup());

  const refusal = { success: false, error: { message: "refused by policy" } };

  const confirmed = [
    {
      name: "suspend",
      open: "Suspend",
      call: () => tenantSvc.suspendTenant,
      args: ["t-1"],
      ok: { success: true, data: {} },
      done: "Tenant suspended",
    },
    {
      name: "DEK rotation",
      open: "Rotate DEK",
      call: () => tenantSvc.rotateDEK,
      args: [{ tenantId: "t-1" }],
      ok: { success: true, data: { oldVersion: 1, newVersion: 2 } },
      done: "DEK rotated from version 1 to 2",
    },
    {
      name: "barrier seal",
      open: "Seal barrier",
      call: () => tenantSvc.sealBarrier,
      args: ["t-1"],
      ok: { success: true, data: {} },
      done: "Barrier sealed",
    },
  ];

  async function open(label: string) {
    render(<TenantDetailClient />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: label }));
    });
    expect(screen.getByTestId("confirm-dialog")).toBeTruthy();
  }

  it.each(confirmed)("sends no $name request when Cancel is chosen", async ({ open: label, call }) => {
    await open(label);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    });
    expect(screen.queryByTestId("confirm-dialog")).toBeNull();
    expect(call()).not.toHaveBeenCalled();
  });

  it.each(confirmed)("sends one $name request for this tenant on Confirm", async ({ open: label, call, args, ok, done }) => {
    call().mockResolvedValue(ok);
    await open(label);
    await act(async () => {
      fireEvent.click(screen.getByTestId("confirm-action"));
    });
    expect(call()).toHaveBeenCalledTimes(1);
    expect(call()).toHaveBeenCalledWith(...args);
    expect(screen.getByTestId("action-result").textContent).toBe(done);
  });

  it.each(confirmed)("shows the refusal message of a $name", async ({ open: label, call, done }) => {
    call().mockResolvedValue(refusal);
    await open(label);
    await act(async () => {
      fireEvent.click(screen.getByTestId("confirm-action"));
    });
    const result = screen.getByTestId("action-result").textContent;
    expect(result).toBe("refused by policy");
    expect(result).not.toBe(done);
  });

  async function saveQuotas(edits: Record<string, string>) {
    render(<TenantDetailClient />);
    for (const [label, value] of Object.entries(edits)) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Save quotas" }));
    });
  }

  it("keeps the other compute limits when one limit is edited", async () => {
    tenantSvc.updateQuotas.mockResolvedValue({ success: true, data: {} });
    await saveQuotas({ "Max vCPUs": "16" });
    expect(tenantSvc.updateQuotas).toHaveBeenCalledTimes(1);
    expect(tenantSvc.updateQuotas).toHaveBeenCalledWith({
      tenantId: "t-1",
      compute: { maxVms: 4, maxContainers: 7, maxVcpus: 16, maxMemoryMb: 1024 },
    });
    expect(screen.getByTestId("action-result").textContent).toBe("Quotas updated");
  });

  it("shows the refusal message of a quota update and keeps the edit", async () => {
    tenantSvc.updateQuotas.mockResolvedValue(refusal);
    await saveQuotas({ "Max VMs": "2" });
    expect(tenantSvc.updateQuotas).toHaveBeenCalledWith({
      tenantId: "t-1",
      compute: { maxVms: 2, maxContainers: 7, maxVcpus: 8, maxMemoryMb: 1024 },
    });
    expect(screen.getByTestId("action-result").textContent).toBe("refused by policy");
    expect((screen.getByLabelText("Max VMs") as HTMLInputElement).value).toBe("2");
  });
});
